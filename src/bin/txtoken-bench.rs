//! Measurement driver. See PREREGISTRO.md for what is measured and why.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::json;
use txtoken::chain::{Mode, Request, Tamper};
use txtoken::demo::{access_token, request_body, Fixture, GATEWAY};
use txtoken::ST_ACCESS_TOKEN;

fn arg(name: &str, default: u64) -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|v| v.parse().expect("number"))
        .unwrap_or(default)
}

fn pct(v: &mut [u64], p: f64) -> f64 {
    v.sort_unstable();
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i] as f64 / 1000.0
}

fn main() {
    let tx = arg("--tx", 5000);
    let tamper_n = arg("--tamper-n", 1000);
    let seed = arg("--seed", 42);
    let f = Fixture::new(seed);
    let mut rng = StdRng::seed_from_u64(seed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    // M1
    let at = access_token(&f.as_key, "d084sdrt234fsaw34tr23t", now, 300);
    let sample = f.issue("d084sdrt234fsaw34tr23t", now);

    // Warm-up: first verification fetches the JWKS once.
    f.verifier.verify(&sample, now).expect("warm-up");
    let fetches_before = f.verifier.jwks.fetches();

    // M2 + M3 + C+
    let mut issue_ns = Vec::with_capacity(tx as usize);
    let mut verify_ns = Vec::with_capacity(tx as usize * 5);
    let mut fwd_ns = Vec::with_capacity(tx as usize * 5);
    let mut accepted_all = 0u64;
    for _ in 0..tx {
        let body = request_body(&at, ST_ACCESS_TOKEN, "trade.stocks");
        let t0 = Instant::now();
        let tok = f
            .tts
            .exchange_form(GATEWAY, &body, now)
            .expect("issue")
            .access_token;
        issue_ns.push(t0.elapsed().as_nanos() as u64);
        let o = f
            .chain
            .run(Request::with_token(&tok), now, Mode::Verify, None);
        if o.accepted == 5 {
            accepted_all += 1;
        }
        verify_ns.extend(o.hop_ns);
        let o = f
            .chain
            .run(Request::with_token(&tok), now, Mode::ForwardOnly, None);
        fwd_ns.extend(o.hop_ns);
    }
    let fetches_chain = f.verifier.jwks.fetches() - fetches_before;

    // M5 and C-
    let mut m5 = serde_json::Map::new();
    let mut cneg = serde_json::Map::new();
    let mut m5_total = 0u64;
    let mut m5_rejected_next = 0u64;
    for t in Tamper::ALL {
        let (mut rej, mut fooled) = (0u64, 0u64);
        for _ in 0..tamper_n {
            let hop = rng.gen_range(0..4);
            let tok = f.issue("u", now);
            let o = f.chain.run(
                Request::with_token(&tok),
                now,
                Mode::Verify,
                Some((hop, t, &f.attacker)),
            );
            if matches!(o.rejected, Some((i, _)) if i == hop + 1) {
                rej += 1;
            }
            let o = f.chain.run(
                Request::with_token(&tok),
                now,
                Mode::InsecureDecodeOnly,
                Some((hop, t, &f.attacker)),
            );
            if o.accepted == 5 {
                fooled += 1;
            }
        }
        m5_total += tamper_n;
        m5_rejected_next += rej;
        m5.insert(t.name().into(), json!(rej));
        cneg.insert(t.name().into(), json!(fooled));
    }

    let v_p50 = pct(&mut verify_ns, 0.50);
    let v_p99 = pct(&mut verify_ns, 0.99);
    let f_p50 = pct(&mut fwd_ns, 0.50);
    let report = json!({
        "params": {"tx": tx, "tamper_n": tamper_n, "seed": seed, "hops": 5},
        "M1_bytes": {"txn_token": sample.len(), "access_token_in": at.len()},
        "M2_issue_us": {"p50": pct(&mut issue_ns, 0.50), "p99": pct(&mut issue_ns, 0.99)},
        "M3_hop_us": {"verify_p50": v_p50, "verify_p99": v_p99,
                      "forward_only_p50": f_p50, "added_p50": v_p50 - f_p50},
        "M4_jwks_fetches_during_chain": fetches_chain,
        "M5_rejected_at_next_hop": {"total": m5_total, "rejected": m5_rejected_next, "per_mode": m5},
        "C_pos_accepted_all_5_hops": {"total": tx, "accepted": accepted_all},
        "C_neg_insecure_fooled": {"per_mode_of": tamper_n, "per_mode": cneg},
        "jwks_fetches_total_incl_tamper": f.verifier.jwks.fetches(),
    });
    println!("{}", serde_json::to_string_pretty(&report).expect("json"));
}
