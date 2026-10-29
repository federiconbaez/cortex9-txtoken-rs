//! Simulated call chain: each workload receives a request, validates the
//! `Txn-Token` header and forwards the token *as received* (Section 12.2) to
//! the next workload. A hop can be made malicious with a [`Tamper`].

use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::jws::{self, b64e};
use crate::verify::{insecure_decode_only, TxnClaims, Verifier};
use crate::{Error, TXN_TOKEN_HEADER, TXN_TOKEN_TYP};

/// A minimal HTTP request: just what the chain needs.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    pub fn with_token(token: &str) -> Self {
        Request {
            headers: vec![(TXN_TOKEN_HEADER.into(), token.into())],
            body: String::new(),
        }
    }

    /// Section 12.1: the header value MUST be exactly one Txn-Token.
    pub fn txn_token(&self) -> Result<&str, Error> {
        let v: Vec<&str> = self
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(TXN_TOKEN_HEADER))
            .map(|(_, v)| v.as_str())
            .collect();
        match v.as_slice() {
            [one] if !one.contains(',') => Ok(one),
            [_] => Err(Error::HeaderCount(2)),
            _ => Err(Error::HeaderCount(v.len())),
        }
    }
}

/// Ways a compromised intermediate workload alters what it forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    /// Change `tctx.quantity`, keep the original signature.
    TctxValue,
    /// Add a field to `tctx`, keep the original signature.
    TctxAddField,
    /// Change `sub`, keep the original signature.
    SubSwap,
    /// Raise `scope`, keep the original signature.
    ScopeEscalate,
    /// Change `tctx` and re-sign with an attacker key under the TTS `kid`.
    ResignForeignKey,
    /// Change `tctx`, set `alg: none` and drop the signature.
    AlgNone,
    /// Splice the altered payload with the signature of another valid token.
    SpliceSignature,
    /// Keep the original token but add a second `Txn-Token` header with an
    /// altered copy.
    DuplicateHeader,
    /// Replace the token with a validly signed one from another Trust Domain.
    CrossDomain,
}

impl Tamper {
    pub const ALL: [Tamper; 9] = [
        Tamper::TctxValue,
        Tamper::TctxAddField,
        Tamper::SubSwap,
        Tamper::ScopeEscalate,
        Tamper::ResignForeignKey,
        Tamper::AlgNone,
        Tamper::SpliceSignature,
        Tamper::DuplicateHeader,
        Tamper::CrossDomain,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Tamper::TctxValue => "tctx_value",
            Tamper::TctxAddField => "tctx_add_field",
            Tamper::SubSwap => "sub_swap",
            Tamper::ScopeEscalate => "scope_escalate",
            Tamper::ResignForeignKey => "resign_foreign_key",
            Tamper::AlgNone => "alg_none",
            Tamper::SpliceSignature => "splice_signature",
            Tamper::DuplicateHeader => "duplicate_header",
            Tamper::CrossDomain => "cross_domain",
        }
    }
}

/// Material the attacker has: its own key, another valid token from the same
/// TTS (for splicing) and a valid token from a foreign Trust Domain.
pub struct Attacker {
    pub key: SigningKey,
    pub other_token: String,
    pub foreign_token: String,
}

fn alter_payload(token: &str, f: impl FnOnce(&mut Value)) -> (Value, Value) {
    let parts = jws::split(token).expect("valid input token");
    let mut p = parts.payload.clone();
    f(&mut p);
    (parts.header, p)
}

fn enc(v: &Value) -> String {
    b64e(serde_json::to_string(v).expect("json").as_bytes())
}

fn keep_sig(token: &str, header: &Value, payload: &Value) -> String {
    let sig = token.rsplit('.').next().expect("sig");
    format!("{}.{}.{sig}", enc(header), enc(payload))
}

fn bump_quantity(p: &mut Value) {
    p["tctx"]["quantity"] = json!("100000");
}

/// Apply `t` to the request a malicious workload is about to forward.
pub fn tamper(req: &Request, t: Tamper, atk: &Attacker) -> Request {
    let token = req.txn_token().expect("one token").to_owned();
    let out = |tok: String| Request::with_token(&tok);
    match t {
        Tamper::TctxValue => {
            let (h, p) = alter_payload(&token, bump_quantity);
            out(keep_sig(&token, &h, &p))
        }
        Tamper::TctxAddField => {
            let (h, p) = alter_payload(&token, |p| p["tctx"]["approved_by"] = json!("attacker"));
            out(keep_sig(&token, &h, &p))
        }
        Tamper::SubSwap => {
            let (h, p) = alter_payload(&token, |p| p["sub"] = json!("victim-admin"));
            out(keep_sig(&token, &h, &p))
        }
        Tamper::ScopeEscalate => {
            let (h, p) = alter_payload(&token, |p| p["scope"] = json!("trade.stocks admin"));
            out(keep_sig(&token, &h, &p))
        }
        Tamper::ResignForeignKey => {
            let (h, p) = alter_payload(&token, bump_quantity);
            out(jws::sign(&h, &p, &atk.key))
        }
        Tamper::AlgNone => {
            let (_, p) = alter_payload(&token, bump_quantity);
            let h = json!({"typ": TXN_TOKEN_TYP, "alg": "none"});
            out(format!("{}.{}.", enc(&h), enc(&p)))
        }
        Tamper::SpliceSignature => {
            let (h, p) = alter_payload(&token, bump_quantity);
            out(keep_sig(&atk.other_token, &h, &p))
        }
        Tamper::DuplicateHeader => {
            let (h, p) = alter_payload(&token, bump_quantity);
            let mut r = req.clone();
            r.headers
                .push((TXN_TOKEN_HEADER.into(), keep_sig(&token, &h, &p)));
            r
        }
        Tamper::CrossDomain => out(atk.foreign_token.clone()),
    }
}

/// One workload of the chain.
pub struct Workload {
    pub name: String,
    pub verifier: Arc<Verifier>,
}

/// Result of pushing one request through the chain.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Hops that accepted the request, in order.
    pub accepted: usize,
    /// Hop index and error where it was rejected.
    pub rejected: Option<(usize, Error)>,
    /// Validation time per hop that ran, nanoseconds.
    pub hop_ns: Vec<u64>,
    /// Claims seen by the last accepting hop.
    pub last_claims: Option<TxnClaims>,
}

pub struct Chain {
    pub hops: Vec<Workload>,
}

/// What each hop does with the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Full Section 12.2 validation.
    Verify,
    /// Negative control: decode-only, signature never checked.
    InsecureDecodeOnly,
    /// Baseline: only extract and forward the header, no validation.
    ForwardOnly,
}

impl Chain {
    pub fn new(names: &[&str], verifier: Arc<Verifier>) -> Self {
        Chain {
            hops: names
                .iter()
                .map(|n| Workload {
                    name: (*n).into(),
                    verifier: verifier.clone(),
                })
                .collect(),
        }
    }

    /// Run `req` through all hops. If `bad` is `Some((i, t))`, hop `i`
    /// forwards a tampered request to hop `i + 1`.
    pub fn run(
        &self,
        mut req: Request,
        now: u64,
        mode: Mode,
        bad: Option<(usize, Tamper, &Attacker)>,
    ) -> Outcome {
        let mut o = Outcome {
            accepted: 0,
            rejected: None,
            hop_ns: Vec::with_capacity(self.hops.len()),
            last_claims: None,
        };
        for (i, hop) in self.hops.iter().enumerate() {
            let t0 = Instant::now();
            let res = req.txn_token().and_then(|tok| match mode {
                Mode::Verify => hop.verifier.verify(tok, now).map(Some),
                Mode::InsecureDecodeOnly => {
                    insecure_decode_only(tok, &hop.verifier.trust_domain, now).map(Some)
                }
                Mode::ForwardOnly => Ok(None),
            });
            // Forward the token exactly as received.
            let next = res
                .as_ref()
                .ok()
                .map(|_| Request::with_token(req.txn_token().expect("validated above")));
            o.hop_ns.push(t0.elapsed().as_nanos() as u64);
            match (res, next) {
                (Ok(c), Some(mut next)) => {
                    o.accepted += 1;
                    if c.is_some() {
                        o.last_claims = c;
                    }
                    if let Some((j, t, atk)) = bad {
                        if j == i {
                            next = tamper(&next, t, atk);
                        }
                    }
                    req = next;
                }
                (Err(e), _) => {
                    o.rejected = Some((i, e));
                    break;
                }
                (Ok(_), None) => unreachable!(),
            }
        }
        o
    }
}
