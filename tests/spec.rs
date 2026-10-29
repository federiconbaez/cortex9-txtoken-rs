//! Behaviour required by draft-ietf-oauth-transaction-tokens-11.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};
use txtoken::chain::{Mode, Request, Tamper};
use txtoken::demo::{access_token, payload, request_body, Fixture, GATEWAY, TRUST_DOMAIN, TTS_ID};
use txtoken::jwks::{Jwk, Jwks, JwksCache};
use txtoken::tts::WorkloadPolicy;
use txtoken::verify::Verifier;
use txtoken::{jws, Error, ST_ACCESS_TOKEN, ST_REFRESH_TOKEN, ST_SELF_SIGNED, ST_UNSIGNED_JSON};

const NOW: u64 = 1_800_000_000;

fn body_with(pairs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

#[test]
fn issuance_matches_sections_9_and_11_4() {
    let f = Fixture::new(1);
    let at = access_token(&f.as_key, "user-42", NOW, 300);
    let resp = f
        .tts
        .exchange_form(
            GATEWAY,
            &request_body(&at, ST_ACCESS_TOKEN, "trade.stocks"),
            NOW,
        )
        .unwrap();
    let j = serde_json::to_value(&resp).unwrap();
    assert_eq!(j["token_type"], "N_A");
    assert_eq!(
        j["issued_token_type"],
        "urn:ietf:params:oauth:token-type:txn_token"
    );
    assert!(j.get("refresh_token").is_none());

    let parts = jws::split(&resp.access_token).unwrap();
    assert_eq!(parts.header["typ"], "txntoken+jwt");
    assert_eq!(parts.header["alg"], "EdDSA");
    assert_eq!(parts.header["kid"], "tts-1");
    let p = parts.payload;
    for c in ["iat", "aud", "exp", "txn", "sub", "scope", "req_wl"] {
        assert!(p.get(c).is_some(), "missing {c}");
    }
    assert_eq!(p["aud"], TRUST_DOMAIN);
    assert_eq!(p["sub"], "user-42");
    assert_eq!(p["req_wl"], GATEWAY);
    assert_eq!(p["scope"], "trade.stocks");
    assert_eq!(p["exp"].as_u64().unwrap() - p["iat"].as_u64().unwrap(), 60);
    assert_eq!(p["tctx"]["ticker"], "MSFT");
    assert_eq!(p["tctx"]["customer_type"]["level"], "VIP");
    assert_eq!(p["rctx"]["authn"], "face");
    let claims = f.verifier.verify(&resp.access_token, NOW + 1).unwrap();
    assert_eq!(claims.sub, "user-42");
}

#[test]
fn txn_is_unique_per_issuance() {
    let f = Fixture::new(2);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        let t = f.issue("u", NOW);
        assert!(seen.insert(payload(&t)["txn"].as_str().unwrap().to_owned()));
    }
}

#[test]
fn request_errors_are_rfc6749_codes() {
    let f = Fixture::new(3);
    let at = access_token(&f.as_key, "u", NOW, 300);
    let good = request_body(&at, ST_ACCESS_TOKEN, "trade.stocks");
    let e = |client: &str, body: &str| f.tts.exchange_form(client, body, NOW).unwrap_err().error;

    assert_eq!(e("unknown.workload", &good), "unauthorized_client");
    assert_eq!(
        e(
            GATEWAY,
            &good.replace("token-exchange", "client_credentials")
        ),
        "unsupported_grant_type"
    );
    assert_eq!(
        e(GATEWAY, &good.replace("txn_token", "access_token")),
        "invalid_request"
    );
    assert_eq!(
        e(
            GATEWAY,
            &good.replace("audience=trust-domain.example", "audience=evil.example")
        ),
        "invalid_target"
    );
    assert_eq!(
        e(GATEWAY, &request_body(&at, ST_ACCESS_TOKEN, "admin")),
        "invalid_scope"
    );
    assert_eq!(
        e(
            GATEWAY,
            &request_body(&at, ST_REFRESH_TOKEN, "trade.stocks")
        ),
        "invalid_request"
    );
    assert_eq!(
        e(GATEWAY, &format!("{good}&scope=admin")),
        "invalid_request"
    );
    let no_subject = body_with(&[
        ("grant_type", txtoken::GRANT_TOKEN_EXCHANGE),
        ("requested_token_type", txtoken::TXN_TOKEN_TYPE),
        ("audience", TRUST_DOMAIN),
        ("scope", "trade.stocks"),
    ]);
    assert_eq!(e(GATEWAY, &no_subject), "invalid_request");
    let bad_details = good.replace("request_details=%7B", "request_details=%5B");
    assert_eq!(e(GATEWAY, &bad_details), "invalid_request");
}

#[test]
fn scope_is_narrowed_to_policy() {
    let f = Fixture::new(4);
    let at = access_token(&f.as_key, "u", NOW, 300);
    let r = f
        .tts
        .exchange_form(
            GATEWAY,
            &request_body(&at, ST_ACCESS_TOKEN, "admin trade.stocks"),
            NOW,
        )
        .unwrap();
    assert_eq!(payload(&r.access_token)["scope"], "trade.stocks");
}

#[test]
fn subject_access_token_is_validated() {
    let f = Fixture::new(5);
    // Section 6: expired subject token -> no Txn-Token.
    let expired = access_token(&f.as_key, "u", NOW, -1);
    let r = f.tts.exchange_form(
        GATEWAY,
        &request_body(&expired, ST_ACCESS_TOKEN, "trade.stocks"),
        NOW,
    );
    assert_eq!(r.unwrap_err().error, "invalid_grant");
    // Forged subject token (signed by a key the TTS does not trust).
    let forged = access_token(
        &SigningKey::generate(&mut StdRng::seed_from_u64(99)),
        "u",
        NOW,
        300,
    );
    let r = f.tts.exchange_form(
        GATEWAY,
        &request_body(&forged, ST_ACCESS_TOKEN, "trade.stocks"),
        NOW,
    );
    assert_eq!(r.unwrap_err().error, "invalid_grant");
}

#[test]
fn self_signed_and_unsigned_subject_types() {
    let mut f = Fixture::new(6);
    let wk = SigningKey::generate(&mut StdRng::seed_from_u64(7));
    f.tts.workloads.insert(
        "batch.trust-domain.example".into(),
        WorkloadPolicy {
            allowed_scopes: ["reports.run".to_string()].into_iter().collect(),
            self_signed_key: Some(wk.verifying_key()),
            allow_unsigned_json: true,
        },
    );
    let ss = |iss: &str, aud: &str, key: &SigningKey| {
        jws::sign(
            &json!({"alg": "EdDSA"}),
            &json!({"iss": iss, "aud": aud, "sub": "svc-batch", "iat": NOW, "exp": NOW + 60}),
            key,
        )
    };
    let client = "batch.trust-domain.example";
    let ok = f
        .tts
        .exchange_form(
            client,
            &request_body(&ss(client, TTS_ID, &wk), ST_SELF_SIGNED, "reports.run"),
            NOW,
        )
        .unwrap();
    assert_eq!(payload(&ok.access_token)["sub"], "svc-batch");
    for bad in [
        ss(client, "other-tts", &wk),
        ss("someone-else", TTS_ID, &wk),
        ss(client, TTS_ID, &f.attacker.key),
    ] {
        let r = f.tts.exchange_form(
            client,
            &request_body(&bad, ST_SELF_SIGNED, "reports.run"),
            NOW,
        );
        assert_eq!(r.unwrap_err().error, "invalid_grant");
    }
    let u = f
        .tts
        .exchange_form(
            client,
            &request_body(r#"{"sub":"job-7"}"#, ST_UNSIGNED_JSON, "reports.run"),
            NOW,
        )
        .unwrap();
    assert_eq!(payload(&u.access_token)["sub"], "job-7");
    // The gateway policy does not allow unsigned_json.
    let r = f.tts.exchange_form(
        GATEWAY,
        &request_body(r#"{"sub":"x"}"#, ST_UNSIGNED_JSON, "trade.stocks"),
        NOW,
    );
    assert_eq!(r.unwrap_err().error, "invalid_request");
}

#[test]
fn verifier_checks_section_12_2() {
    let f = Fixture::new(8);
    let t = f.issue("u", NOW);
    assert!(f.verifier.verify(&t, NOW).is_ok());
    assert_eq!(f.verifier.verify(&t, NOW + 60 + 5), Err(Error::Expired));
    let other = Verifier::new("other-domain.example", f.verifier.jwks.clone());
    assert_eq!(other.verify(&t, NOW), Err(Error::WrongAudience));
    // Correctly signed by the TTS key but with typ JWT: rejected (Section 9.1).
    let mut p = payload(&t);
    p["txn"] = json!("x");
    let parts = jws::split(&t).unwrap();
    let mut h = parts.header.clone();
    h["typ"] = json!("JWT");
    let fake = jws::sign(&h, &p, &f.attacker.key);
    assert!(matches!(
        f.verifier.verify(&fake, NOW),
        Err(Error::WrongTyp(_))
    ));
    // Missing required claim, signed by the real TTS.
    let mut p = payload(&t);
    p.as_object_mut().unwrap().remove("req_wl");
    assert_eq!(
        f.verifier.verify(&f.tts.sign(&p), NOW),
        Err(Error::MissingClaim("req_wl"))
    );
    assert!(matches!(
        f.verifier.verify("a.b", NOW),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn unknown_kid_refreshes_once_for_rotation() {
    let mut rng = StdRng::seed_from_u64(10);
    let k1 = SigningKey::generate(&mut rng);
    let k2 = SigningKey::generate(&mut rng);
    let served = Arc::new(Mutex::new(Jwks {
        keys: vec![Jwk::ed25519("k1", &k1.verifying_key())],
    }));
    let s2 = served.clone();
    let cache = Arc::new(JwksCache::new(move || s2.lock().unwrap().clone()));
    let v = Verifier::new(TRUST_DOMAIN, cache.clone());
    let tok = |kid: &str, k: &SigningKey| {
        jws::sign(
            &json!({"typ": "txntoken+jwt", "alg": "EdDSA", "kid": kid}),
            &json!({"iat": NOW, "exp": NOW + 60, "aud": TRUST_DOMAIN, "txn": "t",
                    "sub": "s", "scope": "x", "req_wl": "w"}),
            k,
        )
    };
    assert!(v.verify(&tok("k1", &k1), NOW).is_ok());
    assert!(v.verify(&tok("k1", &k1), NOW).is_ok());
    assert_eq!(cache.fetches(), 1);
    served
        .lock()
        .unwrap()
        .keys
        .push(Jwk::ed25519("k2", &k2.verifying_key()));
    assert!(v.verify(&tok("k2", &k2), NOW).is_ok());
    assert_eq!(cache.fetches(), 2);
    assert!(matches!(
        v.verify(&tok("k3", &k2), NOW),
        Err(Error::UnknownKid(_))
    ));
}

#[test]
fn header_must_be_exactly_one_token() {
    assert_eq!(Request::default().txn_token(), Err(Error::HeaderCount(0)));
    let mut r = Request::with_token("a.b.c");
    assert_eq!(r.txn_token(), Ok("a.b.c"));
    r.headers.push(("txn-token".into(), "d.e.f".into()));
    assert_eq!(r.txn_token(), Err(Error::HeaderCount(2)));
    assert_eq!(
        Request::with_token("a.b.c, d.e.f").txn_token(),
        Err(Error::HeaderCount(2))
    );
}

#[test]
fn positive_control_full_chain_accepts_offline() {
    let f = Fixture::new(11);
    let warm = f.issue("u", NOW);
    f.verifier.verify(&warm, NOW).unwrap();
    let before = f.verifier.jwks.fetches();
    for _ in 0..200 {
        let t = f.issue("u", NOW);
        let o = f
            .chain
            .run(Request::with_token(&t), NOW, Mode::Verify, None);
        assert_eq!(o.accepted, 5);
        assert!(o.rejected.is_none());
        assert_eq!(o.last_claims.unwrap().tctx.unwrap()["quantity"], "100");
    }
    assert_eq!(
        f.verifier.jwks.fetches(),
        before,
        "verification must be offline"
    );
}

#[test]
fn every_tamper_at_every_hop_is_rejected_by_next_hop() {
    let f = Fixture::new(12);
    for t in Tamper::ALL {
        for hop in 0..4 {
            let tok = f.issue("u", NOW);
            let o = f.chain.run(
                Request::with_token(&tok),
                NOW,
                Mode::Verify,
                Some((hop, t, &f.attacker)),
            );
            let (at, _) = o
                .rejected
                .clone()
                .unwrap_or_else(|| panic!("{t:?} at {hop} accepted"));
            assert_eq!(at, hop + 1, "{t:?}");
            assert_eq!(o.accepted, hop + 1);
        }
    }
}

#[test]
fn negative_control_insecure_verifier_is_fooled() {
    // The harness must be able to see a broken verifier: the decode-only
    // verifier accepts signature-level tampering.
    let f = Fixture::new(13);
    let mut fooled = Vec::new();
    for t in Tamper::ALL {
        let tok = f.issue("u", NOW);
        let o = f.chain.run(
            Request::with_token(&tok),
            NOW,
            Mode::InsecureDecodeOnly,
            Some((1, t, &f.attacker)),
        );
        if o.accepted == 5 {
            fooled.push(t);
        }
    }
    for t in [
        Tamper::TctxValue,
        Tamper::TctxAddField,
        Tamper::SubSwap,
        Tamper::ScopeEscalate,
        Tamper::ResignForeignKey,
        Tamper::AlgNone,
        Tamper::SpliceSignature,
    ] {
        assert!(
            fooled.contains(&t),
            "{t:?} should fool the insecure verifier"
        );
    }
    let v: Value = json!(fooled.len());
    assert_eq!(v, json!(7));
}
