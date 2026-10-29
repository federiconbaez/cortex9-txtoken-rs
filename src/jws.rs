//! Minimal JWS compact serialization with EdDSA (Ed25519).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;

use crate::Error;

pub fn b64e(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64d(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64url"))
}

/// Sign `header` and `payload` (JSON objects) and return the compact JWS.
pub fn sign(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let h = b64e(serde_json::to_string(header).expect("json").as_bytes());
    let p = b64e(serde_json::to_string(payload).expect("json").as_bytes());
    let input = format!("{h}.{p}");
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64e(&sig.to_bytes()))
}

/// A compact JWS split into its parts, header and payload decoded.
#[derive(Debug, Clone)]
pub struct Parts<'a> {
    pub header: Value,
    pub payload: Value,
    pub signing_input: &'a str,
    pub signature: Vec<u8>,
}

/// Split and decode a compact JWS without verifying it.
pub fn split(token: &str) -> Result<Parts<'_>, Error> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(Error::Malformed("segments")),
    };
    let header: Value =
        serde_json::from_slice(&b64d(h)?).map_err(|_| Error::Malformed("header json"))?;
    let payload: Value =
        serde_json::from_slice(&b64d(p)?).map_err(|_| Error::Malformed("payload json"))?;
    if !header.is_object() || !payload.is_object() {
        return Err(Error::Malformed("not an object"));
    }
    let signature = b64d(s)?;
    Ok(Parts {
        header,
        payload,
        signing_input: &token[..h.len() + 1 + p.len()],
        signature,
    })
}

/// Verify an Ed25519 signature over the signing input (strict verification).
pub fn verify_sig(parts: &Parts<'_>, key: &VerifyingKey) -> Result<(), Error> {
    let sig = Signature::from_slice(&parts.signature).map_err(|_| Error::BadSignature)?;
    key.verify_strict(parts.signing_input.as_bytes(), &sig)
        .map_err(|_| Error::BadSignature)
}
