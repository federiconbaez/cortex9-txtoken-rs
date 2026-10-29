//! Transaction Tokens (draft-ietf-oauth-transaction-tokens-11) in Rust.
//!
//! * [`tts`]: a Txn-Token Service that implements the RFC 8693 token
//!   exchange profile of the draft (Sections 10 and 11).
//! * [`verify`]: offline Txn-Token validation (Section 12.2) against a
//!   cached JWKS.
//! * [`chain`]: a simulated call chain of workloads that forward the token in
//!   the `Txn-Token` header (Section 12.1), with tamper injection.

pub mod chain;
pub mod demo;
pub mod error;
pub mod jwks;
pub mod jws;
pub mod tts;
pub mod verify;

pub use error::Error;

/// `typ` header value required by Section 9.1.
pub const TXN_TOKEN_TYP: &str = "txntoken+jwt";
/// Token type URN (Section 11.1).
pub const TXN_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:txn_token";
/// RFC 8693 grant type.
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Subject token types handled by the TTS.
pub const ST_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const ST_SELF_SIGNED: &str = "urn:ietf:params:oauth:token-type:self_signed";
pub const ST_UNSIGNED_JSON: &str = "urn:ietf:params:oauth:token-type:unsigned_json";
pub const ST_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
/// HTTP header used to carry the token between workloads (Section 12.1).
pub const TXN_TOKEN_HEADER: &str = "Txn-Token";
