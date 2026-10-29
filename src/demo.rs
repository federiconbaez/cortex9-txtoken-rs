//! Reproducible fixture shared by the tests and the benchmark: an external
//! authorization server, a TTS for `trust-domain.example`, an API gateway
//! workload and a chain of five internal workloads.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

use crate::chain::{Attacker, Chain};
use crate::jwks::{Jwk, Jwks, JwksCache};
use crate::jws;
use crate::tts::{TokenService, WorkloadPolicy};
use crate::verify::Verifier;
use crate::{GRANT_TOKEN_EXCHANGE, ST_ACCESS_TOKEN, TXN_TOKEN_TYPE};

pub const TRUST_DOMAIN: &str = "trust-domain.example";
pub const TTS_ID: &str = "txn-token-service.trust-domain.example";
pub const GATEWAY: &str = "apigateway.trust-domain.example";
pub const HOPS: [&str; 5] = ["orders", "risk", "pricing", "ledger", "notify"];

pub struct Fixture {
    pub as_key: SigningKey,
    pub tts: TokenService,
    pub verifier: Arc<Verifier>,
    pub chain: Chain,
    pub attacker: Attacker,
}

fn key(rng: &mut StdRng) -> SigningKey {
    SigningKey::generate(rng)
}

/// External access token (what the gateway receives from the client).
pub fn access_token(as_key: &SigningKey, sub: &str, now: u64, ttl: i64) -> String {
    let exp = (now as i64 + ttl).max(0) as u64;
    jws::sign(
        &json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "as-1"}),
        &json!({"iss": "https://as.example", "aud": GATEWAY, "sub": sub,
                "scope": "trade.stocks", "iat": now, "exp": exp}),
        as_key,
    )
}

/// Form body of a Txn-Token Request modelled on Figure 5 of the draft.
pub fn request_body(subject_token: &str, subject_type: &str, scope: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", GRANT_TOKEN_EXCHANGE)
        .append_pair("requested_token_type", TXN_TOKEN_TYPE)
        .append_pair("audience", TRUST_DOMAIN)
        .append_pair("scope", scope)
        .append_pair("subject_token", subject_token)
        .append_pair("subject_token_type", subject_type)
        .append_pair(
            "request_context",
            r#"{"req_ip":"192.0.2.10","authn":"face","transport":"https"}"#,
        )
        .append_pair(
            "request_details",
            r#"{"action":"BUY","ticker":"MSFT","quantity":"100","customer_type":{"geo":"US","level":"VIP"}}"#,
        )
        .finish()
}

impl Fixture {
    /// Deterministic keys from `seed`.
    pub fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let as_key = key(&mut rng);
        let tts_key = key(&mut rng);
        let as_pub = Jwks {
            keys: vec![Jwk::ed25519("as-1", &as_key.verifying_key())],
        };
        let external = Arc::new(JwksCache::new(move || as_pub.clone()));
        let mut tts = TokenService::new(TRUST_DOMAIN, TTS_ID, "tts-1", tts_key, external, GATEWAY);
        tts.workloads.insert(
            GATEWAY.into(),
            WorkloadPolicy {
                allowed_scopes: ["trade.stocks".to_string()].into_iter().collect(),
                ..Default::default()
            },
        );
        let tts_jwks = tts.jwks();
        let cache = Arc::new(
            JwksCache::new(move || tts_jwks.clone()).with_cooldown(Duration::from_secs(30)),
        );
        let verifier = Arc::new(Verifier::new(TRUST_DOMAIN, cache));
        let chain = Chain::new(&HOPS, verifier.clone());

        // Foreign Trust Domain with its own TTS.
        let foreign_as = Jwks {
            keys: vec![Jwk::ed25519("as-1", &as_key.verifying_key())],
        };
        let mut foreign = TokenService::new(
            "other-domain.example",
            "tts.other-domain.example",
            "tts-other-1",
            key(&mut rng),
            Arc::new(JwksCache::new(move || foreign_as.clone())),
            GATEWAY,
        );
        foreign.workloads.insert(
            GATEWAY.into(),
            WorkloadPolicy {
                allowed_scopes: ["trade.stocks".to_string()].into_iter().collect(),
                ..Default::default()
            },
        );
        let foreign_token = foreign.sign(
            &json!({"iat": 0, "exp": u64::MAX / 2, "aud": "other-domain.example",
                          "txn": "foreign", "sub": "victim-admin", "scope": "trade.stocks",
                          "req_wl": GATEWAY, "tctx": {"quantity": "100000"}}),
        );

        let other_token = tts.sign(&json!({"iat": 0, "exp": u64::MAX / 2, "aud": TRUST_DOMAIN,
                                           "txn": "other", "sub": "someone", "scope": "trade.stocks",
                                           "req_wl": GATEWAY}));
        Fixture {
            attacker: Attacker {
                key: key(&mut rng),
                other_token,
                foreign_token,
            },
            as_key,
            tts,
            verifier,
            chain,
        }
    }

    /// Gateway flow: external access token -> Txn-Token.
    pub fn issue(&self, sub: &str, now: u64) -> String {
        let at = access_token(&self.as_key, sub, now, 300);
        self.tts
            .exchange_form(
                GATEWAY,
                &request_body(&at, ST_ACCESS_TOKEN, "trade.stocks"),
                now,
            )
            .expect("issuance")
            .access_token
    }
}

/// Decoded payload, for assertions.
pub fn payload(token: &str) -> Value {
    jws::split(token).expect("token").payload
}
