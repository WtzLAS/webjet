//! Runs every fuzz target on stable Rust (no libFuzzer): its seeds, then
//! pseudo-random mutations of them (bit flips, truncation, splicing, random
//! bytes). This catches regressions in CI; the real fuzzing with coverage
//! feedback is `cargo +nightly fuzz run <target>` (scripts/fuzz.sh).
//!
//! `WEBJET_FUZZ_ITERS` sets the mutations per target (default 2000),
//! `WEBJET_FUZZ_SEED` the RNG seed (default: random, printed on failure).
//! Inputs in `fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/` are
//! replayed too, so a crash found by cargo-fuzz becomes a regression test.

use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use std::panic::AssertUnwindSafe;
use webjet_fuzz::{TARGETS, seeds};

fn mutate(rng: &mut StdRng, input: &[u8], pool: &[Vec<u8>]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..rng.random_range(1..=4) {
        match rng.random_range(0..7) {
            0 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] ^= 1 << rng.random_range(0..8);
            }
            1 if !v.is_empty() => {
                let i = rng.random_range(0..v.len());
                v[i] = rng.random();
            }
            2 => {
                let n = rng.random_range(0..=v.len());
                v.truncate(n);
            }
            3 => {
                let i = rng.random_range(0..=v.len());
                let n = rng.random_range(1..32);
                let mut extra = vec![0u8; n];
                rng.fill_bytes(&mut extra);
                v.splice(i..i, extra);
            }
            4 if !pool.is_empty() => {
                let other = &pool[rng.random_range(0..pool.len())];
                let i = rng.random_range(0..=v.len());
                let j = rng.random_range(0..=other.len());
                v.truncate(i);
                v.extend_from_slice(&other[j..]);
            }
            5 if !v.is_empty() => {
                // Interesting values for length and count fields.
                let i = rng.random_range(0..v.len());
                const MAGIC: [u8; 6] = [0, 1, 0x7f, 0x80, 0xfe, 0xff];
                v[i] = MAGIC[rng.random_range(0..MAGIC.len())];
            }
            _ => {
                let n = rng.random_range(0..64);
                v = vec![0u8; n];
                rng.fill_bytes(&mut v);
            }
        }
    }
    v
}

/// Files a previous fuzzing run left for `target`.
fn saved(target: &str) -> Vec<Vec<u8>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for dir in ["corpus", "artifacts", "regressions"] {
        let Ok(rd) = std::fs::read_dir(base.join(dir).join(target)) else {
            continue;
        };
        for e in rd.flatten() {
            if let Ok(b) = std::fs::read(e.path()) {
                out.push(b);
            }
        }
    }
    out
}

#[test]
fn every_target_survives_seeds_and_mutations() {
    let iters: usize = std::env::var("WEBJET_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let seed: u64 = std::env::var("WEBJET_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(rand::random);
    // The targets' own assertions report through the panic; keep the
    // output short.
    std::panic::set_hook(Box::new(|_| {}));
    let mut failures = Vec::new();
    for (name, f) in TARGETS {
        let mut pool = seeds::for_target(name);
        assert!(!pool.is_empty(), "{name} has no seeds");
        pool.extend(saved(name));
        let mut rng = StdRng::seed_from_u64(seed ^ name.len() as u64);
        let mut inputs: Vec<Vec<u8>> = pool.clone();
        inputs.push(Vec::new());
        for _ in 0..iters {
            let base = &pool[rng.random_range(0..pool.len())];
            inputs.push(mutate(&mut rng, base, &pool));
        }
        for input in inputs {
            if let Err(p) = std::panic::catch_unwind(AssertUnwindSafe(|| f(&input))) {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                failures.push(format!("{name}: {msg}\n  input: {}", hex(&input)));
                break;
            }
        }
    }
    let _ = std::panic::take_hook();
    assert!(
        failures.is_empty(),
        "seed {seed} (WEBJET_FUZZ_SEED={seed} to repeat):\n{}",
        failures.join("\n")
    );
}

#[test]
fn seeds_reach_past_the_first_checks() {
    // Each seed must be accepted by at least the outer parser, or the
    // fuzzer starts from nothing useful.
    use webjet_core::{frames, packet};
    for s in seeds::for_target("frames") {
        assert!(frames::parse_header(&s).is_some() || frames::parse_relay(&s).is_some());
    }
    for s in seeds::for_target("packet") {
        assert!(packet::parse(&s).is_some(), "{}", hex(&s));
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().take(256).map(|x| format!("{x:02x}")).collect()
}
