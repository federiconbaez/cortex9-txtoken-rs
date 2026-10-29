use std::fmt;

/// Validation error for a JWS / Txn-Token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not three base64url segments, bad base64 or bad JSON.
    Malformed(&'static str),
    /// `alg` is not `EdDSA` (this includes `none`).
    UnsupportedAlg(String),
    /// `typ` header is not `txntoken+jwt`.
    WrongTyp(String),
    /// `kid` header missing.
    MissingKid,
    /// `kid` not present in the JWKS, even after one refresh.
    UnknownKid(String),
    /// Signature does not verify.
    BadSignature,
    /// `aud` does not identify the verifier's Trust Domain.
    WrongAudience,
    /// `exp` is in the past.
    Expired,
    /// `iat` is in the future beyond the leeway.
    IssuedInFuture,
    /// A REQUIRED claim (Section 9.2) is missing or has the wrong type.
    MissingClaim(&'static str),
    /// The request carried zero or more than one `Txn-Token` header.
    HeaderCount(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(w) => write!(f, "malformed token: {w}"),
            Error::UnsupportedAlg(a) => write!(f, "unsupported alg {a:?}"),
            Error::WrongTyp(t) => write!(f, "wrong typ {t:?}"),
            Error::MissingKid => write!(f, "missing kid"),
            Error::UnknownKid(k) => write!(f, "unknown kid {k:?}"),
            Error::BadSignature => write!(f, "bad signature"),
            Error::WrongAudience => write!(f, "aud is not this trust domain"),
            Error::Expired => write!(f, "token expired"),
            Error::IssuedInFuture => write!(f, "iat in the future"),
            Error::MissingClaim(c) => write!(f, "missing or invalid claim {c}"),
            Error::HeaderCount(n) => write!(f, "expected exactly one Txn-Token header, got {n}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Short stable label used in reports.
    pub fn label(&self) -> &'static str {
        match self {
            Error::Malformed(_) => "malformed",
            Error::UnsupportedAlg(_) => "unsupported_alg",
            Error::WrongTyp(_) => "wrong_typ",
            Error::MissingKid => "missing_kid",
            Error::UnknownKid(_) => "unknown_kid",
            Error::BadSignature => "bad_signature",
            Error::WrongAudience => "wrong_audience",
            Error::Expired => "expired",
            Error::IssuedInFuture => "issued_in_future",
            Error::MissingClaim(_) => "missing_claim",
            Error::HeaderCount(_) => "header_count",
        }
    }
}
