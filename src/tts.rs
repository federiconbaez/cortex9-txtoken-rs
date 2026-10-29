//! Txn-Token Service (draft Sections 10 and 11): RFC 8693 token exchange that
//! turns a subject token into a short-lived Txn-Token.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::jwks::{Jwk, Jwks, JwksCache};
use crate::jws;
use crate::{
    GRANT_TOKEN_EXCHANGE, ST_ACCESS_TOKEN, ST_REFRESH_TOKEN, ST_SELF_SIGNED, ST_UNSIGNED_JSON,
    TXN_TOKEN_TYP, TXN_TOKEN_TYPE,
};

/// Successful Txn-Token Response (Section 11.4). There is intentionally no
/// `refresh_token` field.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub token_type: String,
    pub issued_token_type: String,
    pub access_token: String,
}

/// RFC 6749 Section 5.2 error response.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OAuthError {
    pub error: &'static str,
    pub error_description: String,
}

fn err(error: &'static str, d: impl Into<String>) -> OAuthError {
    OAuthError {
        error,
        error_description: d.into(),
    }
}

/// Issuance policy for one requesting workload (Section 13.10).
#[derive(Debug, Clone, Default)]
pub struct WorkloadPolicy {
    /// Scopes this workload may obtain.
    pub allowed_scopes: HashSet<String>,
    /// Key the workload uses for `self_signed` subject tokens, if any.
    pub self_signed_key: Option<ed25519_dalek::VerifyingKey>,
    /// Whether `unsigned_json` subject tokens are accepted from it.
    pub allow_unsigned_json: bool,
}

pub struct TokenService {
    /// Trust Domain, used as `aud`.
    pub trust_domain: String,
    /// TTS identifier, the `aud` expected in self-signed subject tokens.
    pub tts_id: String,
    pub kid: String,
    signing_key: SigningKey,
    /// Lifetime of issued tokens, seconds (Section 6: minutes or less).
    pub lifetime: u64,
    /// Keys of the external authorization server(s) that sign access tokens.
    pub external_as: Arc<JwksCache>,
    /// Expected `aud` of external access tokens.
    pub external_audience: String,
    pub workloads: HashMap<String, WorkloadPolicy>,
}

impl TokenService {
    pub fn new(
        trust_domain: &str,
        tts_id: &str,
        kid: &str,
        signing_key: SigningKey,
        external_as: Arc<JwksCache>,
        external_audience: &str,
    ) -> Self {
        TokenService {
            trust_domain: trust_domain.into(),
            tts_id: tts_id.into(),
            kid: kid.into(),
            signing_key,
            lifetime: 60,
            external_as,
            external_audience: external_audience.into(),
            workloads: HashMap::new(),
        }
    }

    /// Public keys for verifiers (what a `jwks_uri` would serve).
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![Jwk::ed25519(&self.kid, &self.signing_key.verifying_key())],
        }
    }

    /// Handle an `application/x-www-form-urlencoded` Txn-Token Request.
    ///
    /// `client` is the identity of the requesting workload as established by
    /// the transport (mutual TLS or similar, Section 11.5); authenticating it
    /// is outside this crate.
    pub fn exchange_form(
        &self,
        client: &str,
        body: &str,
        now: u64,
    ) -> Result<TokenResponse, OAuthError> {
        let mut params: HashMap<String, String> = HashMap::new();
        for (k, v) in form_urlencoded::parse(body.as_bytes()) {
            if params.insert(k.to_string(), v.to_string()).is_some() {
                return Err(err("invalid_request", format!("duplicate parameter {k}")));
            }
        }
        let get = |k: &str| {
            params
                .get(k)
                .map(String::as_str)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| err("invalid_request", format!("missing {k}")))
        };

        let policy = self
            .workloads
            .get(client)
            .ok_or_else(|| err("unauthorized_client", "workload not registered"))?;
        if get("grant_type")? != GRANT_TOKEN_EXCHANGE {
            return Err(err("unsupported_grant_type", "expected token-exchange"));
        }
        if get("requested_token_type")? != TXN_TOKEN_TYPE {
            return Err(err(
                "invalid_request",
                "requested_token_type must be txn_token",
            ));
        }
        if get("audience")? != self.trust_domain {
            return Err(err("invalid_target", "audience is not this trust domain"));
        }
        let requested_scope = get("scope")?;
        let subject_token = get("subject_token")?;
        let subject_type = get("subject_token_type")?;

        let sub = match subject_type {
            ST_ACCESS_TOKEN => self.check_access_token(subject_token, now)?,
            ST_SELF_SIGNED => self.check_self_signed(policy, client, subject_token, now)?,
            ST_UNSIGNED_JSON => {
                if !policy.allow_unsigned_json {
                    return Err(err(
                        "invalid_request",
                        "unsigned_json not allowed for workload",
                    ));
                }
                let v: Value = serde_json::from_str(subject_token)
                    .map_err(|_| err("invalid_request", "subject_token is not JSON"))?;
                v.get("sub")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| err("invalid_request", "unsigned_json without sub"))?
            }
            ST_REFRESH_TOKEN => {
                return Err(err(
                    "invalid_request",
                    "refresh_token subject type is not allowed",
                ))
            }
            other => {
                return Err(err(
                    "invalid_request",
                    format!("unknown subject_token_type {other}"),
                ))
            }
        };

        let scopes: Vec<&str> = requested_scope
            .split(' ')
            .filter(|s| !s.is_empty() && policy.allowed_scopes.contains(*s))
            .collect();
        if scopes.is_empty() {
            return Err(err(
                "invalid_scope",
                "no requested scope is allowed for workload",
            ));
        }

        let obj = |k: &str| -> Result<Option<Map<String, Value>>, OAuthError> {
            match params.get(k) {
                None => Ok(None),
                Some(s) => match serde_json::from_str::<Value>(s) {
                    Ok(Value::Object(m)) => Ok(Some(m)),
                    _ => Err(err("invalid_request", format!("{k} must be a JSON object"))),
                },
            }
        };
        let rctx = obj("request_context")?;
        let tctx = obj("request_details")?;

        let mut payload = json!({
            "iat": now,
            "exp": now + self.lifetime,
            "aud": self.trust_domain,
            "txn": uuid::Uuid::new_v4().to_string(),
            "sub": sub,
            "scope": scopes.join(" "),
            "req_wl": client,
        });
        if let Some(r) = rctx {
            payload["rctx"] = Value::Object(r);
        }
        if let Some(t) = tctx {
            payload["tctx"] = Value::Object(t);
        }
        Ok(TokenResponse {
            token_type: "N_A".into(),
            issued_token_type: TXN_TOKEN_TYPE.into(),
            access_token: self.sign(&payload),
        })
    }

    /// Sign a Txn-Token payload with the TTS key and `typ: txntoken+jwt`.
    pub fn sign(&self, payload: &Value) -> String {
        let header = json!({"typ": TXN_TOKEN_TYP, "alg": "EdDSA", "kid": self.kid});
        jws::sign(&header, payload, &self.signing_key)
    }

    fn check_access_token(&self, token: &str, now: u64) -> Result<String, OAuthError> {
        let bad = |d: &str| err("invalid_grant", d.to_string());
        let parts = jws::split(token).map_err(|_| bad("subject_token malformed"))?;
        if parts.header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(bad("subject_token alg"));
        }
        let kid = parts
            .header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("subject_token kid"))?;
        let key = self
            .external_as
            .get(kid)
            .map_err(|_| bad("subject_token kid unknown"))?;
        jws::verify_sig(&parts, &key).map_err(|_| bad("subject_token signature"))?;
        let p = &parts.payload;
        if p.get("aud").and_then(Value::as_str) != Some(self.external_audience.as_str()) {
            return Err(bad("subject_token aud"));
        }
        // Section 6: MUST NOT issue if the presented token has expired.
        match p.get("exp").and_then(Value::as_u64) {
            Some(exp) if exp > now => {}
            _ => return Err(bad("subject_token expired or without exp")),
        }
        p.get("sub")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| bad("subject_token without sub"))
    }

    fn check_self_signed(
        &self,
        policy: &WorkloadPolicy,
        client: &str,
        token: &str,
        now: u64,
    ) -> Result<String, OAuthError> {
        let bad = |d: &str| err("invalid_grant", d.to_string());
        let key = policy
            .self_signed_key
            .as_ref()
            .ok_or_else(|| bad("workload has no self-signed key"))?;
        let parts = jws::split(token).map_err(|_| bad("subject_token malformed"))?;
        if parts.header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
            return Err(bad("subject_token alg"));
        }
        jws::verify_sig(&parts, key).map_err(|_| bad("subject_token signature"))?;
        let p = &parts.payload;
        // Section 11.2.1: iss = requesting workload, aud = TTS id, iat, exp.
        if p.get("iss").and_then(Value::as_str) != Some(client) {
            return Err(bad("self_signed iss is not the requesting workload"));
        }
        if p.get("aud").and_then(Value::as_str) != Some(self.tts_id.as_str()) {
            return Err(bad("self_signed aud is not this TTS"));
        }
        let iat = p
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("self_signed iat"))?;
        if iat > now + 30 || now.saturating_sub(iat) > 300 {
            return Err(bad("self_signed iat out of window"));
        }
        match p.get("exp").and_then(Value::as_u64) {
            Some(exp) if exp > now => {}
            _ => return Err(bad("self_signed expired or without exp")),
        }
        p.get("sub")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| bad("self_signed without sub"))
    }
}
