//! JWKS with OKP/Ed25519 keys and a cache that counts fetches, so the
//! benchmark can prove verification is offline after warm-up.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::jws::{b64d, b64e};
use crate::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
}

impl Jwk {
    pub fn ed25519(kid: &str, key: &VerifyingKey) -> Self {
        Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: b64e(key.as_bytes()),
            kid: kid.into(),
            alg: "EdDSA".into(),
            use_: "sig".into(),
        }
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(Error::UnsupportedAlg(format!("{}/{}", self.kty, self.crv)));
        }
        let raw: [u8; 32] = b64d(&self.x)?
            .try_into()
            .map_err(|_| Error::Malformed("jwk x length"))?;
        VerifyingKey::from_bytes(&raw).map_err(|_| Error::Malformed("jwk x point"))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

type Fetcher = Box<dyn Fn() -> Jwks + Send + Sync>;

/// Cache of verification keys keyed by `kid`. On an unknown `kid` it calls the
/// fetcher once (key rotation, Section 13.11) and gives up if still unknown.
pub struct JwksCache {
    keys: RwLock<HashMap<String, VerifyingKey>>,
    fetcher: Fetcher,
    fetches: AtomicU64,
    cooldown: Duration,
    last_refresh: Mutex<Option<Instant>>,
}

impl JwksCache {
    pub fn new(fetcher: impl Fn() -> Jwks + Send + Sync + 'static) -> Self {
        JwksCache {
            keys: RwLock::new(HashMap::new()),
            fetcher: Box::new(fetcher),
            fetches: AtomicU64::new(0),
            cooldown: Duration::ZERO,
            last_refresh: Mutex::new(None),
        }
    }

    /// Minimum time between two refreshes triggered by unknown `kid`s, so a
    /// stream of forged `kid`s cannot turn every request into a JWKS fetch.
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// Number of times the fetcher was called.
    pub fn fetches(&self) -> u64 {
        self.fetches.load(Ordering::Relaxed)
    }

    fn refresh(&self) {
        {
            let mut last = self.last_refresh.lock().expect("lock");
            if let Some(t) = *last {
                if t.elapsed() < self.cooldown {
                    return;
                }
            }
            *last = Some(Instant::now());
        }
        self.fetches.fetch_add(1, Ordering::Relaxed);
        let jwks = (self.fetcher)();
        let mut map = HashMap::new();
        for k in &jwks.keys {
            if let Ok(vk) = k.verifying_key() {
                map.insert(k.kid.clone(), vk);
            }
        }
        *self.keys.write().expect("lock") = map;
    }

    pub fn get(&self, kid: &str) -> Result<VerifyingKey, Error> {
        if let Some(k) = self.keys.read().expect("lock").get(kid) {
            return Ok(*k);
        }
        self.refresh();
        self.keys
            .read()
            .expect("lock")
            .get(kid)
            .copied()
            .ok_or_else(|| Error::UnknownKid(kid.into()))
    }
}
