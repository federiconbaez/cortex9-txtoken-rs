//! Offline Txn-Token validation (draft Section 12.2 plus the header and claim
//! requirements of Section 9).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwks::JwksCache;
use crate::jws;
use crate::{Error, TXN_TOKEN_TYP};

/// Claims of a validated Txn-Token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxnClaims {
    pub iat: u64,
    pub exp: u64,
    pub aud: String,
    pub txn: String,
    pub sub: String,
    pub scope: String,
    pub req_wl: String,
    pub tctx: Option<Value>,
    pub rctx: Option<Value>,
    pub iss: Option<String>,
}

pub struct Verifier {
    pub trust_domain: String,
    pub jwks: Arc<JwksCache>,
    /// Clock skew tolerated for `exp` and `iat`, seconds.
    pub leeway: u64,
}

fn req_u64(p: &Value, name: &'static str) -> Result<u64, Error> {
    p.get(name)
        .and_then(Value::as_u64)
        .ok_or(Error::MissingClaim(name))
}

fn req_str(p: &Value, name: &'static str) -> Result<String, Error> {
    p.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::MissingClaim(name))
}

fn opt_obj(p: &Value, name: &'static str) -> Result<Option<Value>, Error> {
    match p.get(name) {
        None => Ok(None),
        Some(v) if v.is_object() => Ok(Some(v.clone())),
        Some(_) => Err(Error::MissingClaim(name)),
    }
}

impl Verifier {
    pub fn new(trust_domain: &str, jwks: Arc<JwksCache>) -> Self {
        Verifier {
            trust_domain: trust_domain.into(),
            jwks,
            leeway: 5,
        }
    }

    /// Validate `token` at time `now` (unix seconds).
    pub fn verify(&self, token: &str, now: u64) -> Result<TxnClaims, Error> {
        let parts = jws::split(token)?;
        let h = &parts.header;
        let alg = h.get("alg").and_then(Value::as_str).unwrap_or("");
        if alg != "EdDSA" {
            return Err(Error::UnsupportedAlg(alg.into()));
        }
        let typ = h.get("typ").and_then(Value::as_str).unwrap_or("");
        if typ != TXN_TOKEN_TYP {
            return Err(Error::WrongTyp(typ.into()));
        }
        let kid = h
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(Error::MissingKid)?;
        let key = self.jwks.get(kid)?;
        jws::verify_sig(&parts, &key)?;

        let p = &parts.payload;
        let aud_ok = match p.get("aud") {
            Some(Value::String(a)) => a == &self.trust_domain,
            Some(Value::Array(v)) => v.iter().any(|a| a.as_str() == Some(&self.trust_domain)),
            _ => return Err(Error::MissingClaim("aud")),
        };
        let iat = req_u64(p, "iat")?;
        let exp = req_u64(p, "exp")?;
        let claims = TxnClaims {
            iat,
            exp,
            aud: self.trust_domain.clone(),
            txn: req_str(p, "txn")?,
            sub: req_str(p, "sub")?,
            scope: req_str(p, "scope")?,
            req_wl: req_str(p, "req_wl")?,
            tctx: opt_obj(p, "tctx")?,
            rctx: opt_obj(p, "rctx")?,
            iss: p.get("iss").and_then(Value::as_str).map(str::to_owned),
        };
        if !aud_ok {
            return Err(Error::WrongAudience);
        }
        if now >= exp.saturating_add(self.leeway) {
            return Err(Error::Expired);
        }
        if iat > now.saturating_add(self.leeway) {
            return Err(Error::IssuedInFuture);
        }
        Ok(claims)
    }
}

/// Deliberately broken verifier used ONLY as the negative control of the
/// tamper experiment: it decodes and checks claims but never checks the
/// signature. A harness that cannot tell this apart from [`Verifier`] would be
/// worthless.
pub fn insecure_decode_only(token: &str, trust_domain: &str, now: u64) -> Result<TxnClaims, Error> {
    let parts = jws::split(token)?;
    let p = &parts.payload;
    let aud = req_str(p, "aud")?;
    if aud != trust_domain {
        return Err(Error::WrongAudience);
    }
    let exp = req_u64(p, "exp")?;
    if now >= exp {
        return Err(Error::Expired);
    }
    Ok(TxnClaims {
        iat: req_u64(p, "iat")?,
        exp,
        aud,
        txn: req_str(p, "txn")?,
        sub: req_str(p, "sub")?,
        scope: req_str(p, "scope")?,
        req_wl: req_str(p, "req_wl")?,
        tctx: opt_obj(p, "tctx")?,
        rctx: opt_obj(p, "rctx")?,
        iss: None,
    })
}
