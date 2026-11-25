//! Off-chain timings of every scheme and step, for the committee sizes of the
//! paper. Prints a CSV table (one row per scheme, step and n) to stdout.
//!
//! Usage: `cargo run --release --bin timings -- [--n 5,10] [--iters 30] [--scheme glow-msp]`
//!
//! Each value is the median over `iters` runs after a warm-up run, in
//! microseconds. Steps measured per party are reported per party. "combine"
//! includes the checks of all contributions of the quorum, i.e., the full work
//! of the combiner after it received the messages of the parties.

use advrf::common::*;
use advrf::{ddh, glow, glowp, icy};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

const DEFAULT_N: [usize; 7] = [5, 6, 7, 10, 25, 50, 100];

struct Bench {
    iters: usize,
}

impl Bench {
    fn time<T>(&self, mut f: impl FnMut() -> T) -> f64 {
        std::hint::black_box(f());
        let mut v: Vec<f64> = (0..self.iters)
            .map(|_| {
                let t0 = Instant::now();
                std::hint::black_box(f());
                t0.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }
}

fn row(scheme: &str, step: &str, p: &Params, q: usize, us: f64) {
    println!("{scheme},{step},{},{},{q},{us:.1}", p.n, p.t);
}

fn glow_family(b: &Bench, p: &Params, rng: &mut StdRng, which: &[&str]) {
    let x = [7u8; 32];
    let q = p.min_quorum();
    if which.contains(&"glow") {
        let k = glow::setup(rng, *p);
        let parts: Vec<glow::Partial> = q.iter().map(|&i| glow::peval(rng, &k, i, &x)).collect();
        let (y, sigma) = glow::combine(&k, &x, &parts).unwrap();
        let s = "GLOW-DVRF";
        row(s, "peval", p, q.len(), b.time(|| glow::peval(&mut StdRng::seed_from_u64(1), &k, 1, &x)));
        row(s, "pver", p, q.len(), b.time(|| glow::pver(&k, &x, &parts[0])));
        row(s, "combine", p, q.len(), b.time(|| glow::combine(&k, &x, &parts)));
        row(s, "verify", p, q.len(), b.time(|| glow::verify(&k.pk, &x, &y, &sigma)));
    }
    if which.contains(&"glow-msp") || which.contains(&"glow-asm") {
        let s = "GLOW-A MSP-pop";
        let k = glow::msp_setup(rng, *p);
        if which.contains(&"glow-msp") {
            row(s, "keygen", p, q.len(), b.time(|| glow::msp_keygen(&mut StdRng::seed_from_u64(2))));
            row(s, "setup-pop-check", p, q.len(), b.time(|| {
                (1..p.n).all(|j| glow::pop_verify(&k.ak[j], &k.pop[j]))
            }));
            let parts: Vec<glow::AccPartial> = q.iter().map(|&i| glow::msp_peval(rng, &k, i, &x)).collect();
            let (y, pi) = glow::msp_combine(&k, &x, &parts).unwrap();
            row(s, "peval", p, q.len(), b.time(|| glow::msp_peval(&mut StdRng::seed_from_u64(1), &k, 1, &x)));
            row(s, "pver", p, q.len(), b.time(|| glow::msp_pver(&k, &x, &parts[0])));
            row(s, "combine", p, q.len(), b.time(|| glow::msp_combine(&k, &x, &parts)));
            row(s, "verify", p, q.len(), b.time(|| {
                glow::msp_verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &x, &y, &pi)
            }));
        }
        if which.contains(&"glow-asm") {
            let s = "GLOW-A ASM-pop";
            let k = glow::asm_setup(rng, *p);
            row(s, "setup-pop-check", p, q.len(), b.time(|| {
                (1..p.n).all(|j| glow::pop_verify(&k.msp.ak[j], &k.msp.pop[j]))
            }));
            // Group setup of one party: send mu_{j,i} to every j, then build
            // and check its own membership key from the n received values.
            row(s, "setup-group", p, q.len(), b.time(|| {
                let a = k.msp.a[0];
                let sent: Vec<G1> = (1..=p.n).map(|j| glow::asm_mu(&k.apk_hash, j, &a)).collect();
                let mk: G1 = sent.iter().sum();
                let h6 = glow::asm_h6(&k.apk_hash, 1);
                pairing_check(&[(mk, -g2_generator()), (h6, k.y_agg)])
            }));
            let parts: Vec<glow::AccPartial> = q.iter().map(|&i| glow::asm_peval(rng, &k, i, &x)).collect();
            let (y, pi) = glow::asm_combine(&k, &x, &parts).unwrap();
            row(s, "peval", p, q.len(), b.time(|| glow::asm_peval(&mut StdRng::seed_from_u64(1), &k, 1, &x)));
            row(s, "pver", p, q.len(), b.time(|| glow::asm_pver(&k, &x, &parts[0])));
            row(s, "combine", p, q.len(), b.time(|| glow::asm_combine(&k, &x, &parts)));
            let g = &k.msp.glow;
            row(s, "verify", p, q.len(), b.time(|| {
                glow::asm_verify(&g.pk, &g.pp_hash, &k.apk_hash, &k.y_agg, &k.h6, p.t, &x, &y, &pi)
            }));
        }
    }
}

fn glowp_bench(b: &Bench, p: &Params, rng: &mut StdRng) {
    let x = [7u8; 32];
    let q = p.min_quorum();
    let k = glow::msp_setup(rng, *p);
    let (crs, td) = glowp::binding_setup(rng);
    let parts: Vec<glow::AccPartial> = q.iter().map(|&i| glow::msp_peval(rng, &k, i, &x)).collect();
    let (y, pi) = glowp::combine_checked(rng, &k, &crs, &x, &parts);
    let (set, omega) = glowp::trace(&td, &k, &crs, &x, &y, &pi).unwrap();
    let s = "GLOW-P";
    row(s, "crs-setup", p, q.len(), b.time(|| glowp::binding_setup(&mut StdRng::seed_from_u64(4))));
    row(s, "peval", p, q.len(), b.time(|| glow::msp_peval(&mut StdRng::seed_from_u64(1), &k, 1, &x)));
    row(s, "pver", p, q.len(), b.time(|| glow::msp_pver(&k, &x, &parts[0])));
    // Checks of the t+1 contributions and the Groth–Sahai proof.
    row(s, "combine", p, q.len(), b.time(|| {
        let ok = parts.iter().all(|c| glow::msp_pver(&k, &x, c));
        (ok, glowp::combine_checked(&mut StdRng::seed_from_u64(5), &k, &crs, &x, &parts))
    }));
    row(s, "verify", p, q.len(), b.time(|| {
        glowp::verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &pi)
    }));
    row(s, "trace", p, q.len(), b.time(|| glowp::trace(&td, &k, &crs, &x, &y, &pi)));
    row(s, "judge", p, q.len(), b.time(|| glowp::judge(&k, &x, &set, &omega)));
}

fn ddh_bench(b: &Bench, p: &Params, rng: &mut StdRng) {
    let x = [7u8; 32];
    let q = p.min_quorum();
    let k = ddh::setup(rng, *p);
    let parts: Vec<ddh::Partial> = q.iter().map(|&i| ddh::peval(rng, &k, i, &x)).collect();
    let (y, pi) = ddh::combine(&k, &x, &parts).unwrap();
    let h = ddh::hash_input(&x);
    let s = "DDH-DVRF";
    row(s, "peval", p, q.len(), b.time(|| ddh::peval(&mut StdRng::seed_from_u64(1), &k, 1, &x)));
    row(s, "pver", p, q.len(), b.time(|| ddh::pver(&k.vks, &h, &parts[0])));
    row(s, "combine", p, q.len(), b.time(|| ddh::combine(&k, &x, &parts)));
    row(s, "verify", p, q.len(), b.time(|| ddh::verify(&k.vks, p.t, &x, &y, &pi)));
}

fn icy_bench(b: &Bench, p: &Params, rng: &mut StdRng, variant: icy::Variant) {
    let x = [7u8; 32];
    let set = p.min_quorum();
    let k = icy::setup(rng, *p, variant);
    let toks: Vec<icy::Token> = set.iter().map(|_| icy::preprocess(rng, variant)).collect();
    let req = icy::Request { x, set: set.clone(), tokens: toks.iter().map(|t| t.public).collect() };
    let ctx = (variant == icy::Variant::IcyA).then(|| icy::musig_ctx(&k, &req));
    let msgs: Vec<icy::Round1> = set
        .iter()
        .zip(&toks)
        .map(|(&i, t)| icy::round1(rng, &k, variant, i, &req, t, ctx.as_ref()).unwrap())
        .collect();
    let zs: Vec<_> = set
        .iter()
        .zip(&toks)
        .map(|(&i, t)| icy::round2(&k, variant, i, &req, &msgs, t).unwrap())
        .collect();
    let (y, pi) = icy::combine(&k, variant, &req, &msgs, &zs, ctx.as_ref()).unwrap();
    let s = variant.name();
    let q = set.len();
    row(s, "preprocess-token", p, q, b.time(|| icy::preprocess(&mut StdRng::seed_from_u64(3), variant)));
    // A party derives the MuSig2 context itself in round 1 (Icy-A).
    row(s, "round1", p, q, b.time(|| {
        let c = (variant == icy::Variant::IcyA).then(|| icy::musig_ctx(&k, &req));
        icy::round1(&mut StdRng::seed_from_u64(1), &k, variant, set[0], &req, &toks[0], c.as_ref())
    }));
    row(s, "round2", p, q, b.time(|| icy::round2(&k, variant, set[0], &req, &msgs, &toks[0])));
    row(s, "combine", p, q, b.time(|| icy::combine(&k, variant, &req, &msgs, &zs, ctx.as_ref())));
    row(s, "verify", p, q, b.time(|| icy::verify(variant, &k.pk, &k.pp_hash, &k.xk, p.t, &x, &y, &pi)));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |name: &str| args.iter().position(|a| a == name).map(|i| args[i + 1].clone());
    let ns: Vec<usize> = get("--n")
        .map(|s| s.split(',').map(|v| v.parse().unwrap()).collect())
        .unwrap_or(DEFAULT_N.to_vec());
    let iters: usize = get("--iters").map(|s| s.parse().unwrap()).unwrap_or(30);
    let all = ["glow", "glow-msp", "glow-asm", "glow-p", "ddh", "icy", "icy-n", "icy-a"];
    let schemes: Vec<String> = get("--scheme")
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or(all.iter().map(|s| s.to_string()).collect());
    let which: Vec<&str> = schemes.iter().map(|s| s.as_str()).collect();
    let b = Bench { iters };
    let mut rng = StdRng::seed_from_u64(2026);
    println!("scheme,step,n,t,quorum,median_us");
    for &n in &ns {
        let p = Params::honest_majority(n);
        glow_family(&b, &p, &mut rng, &which);
        if which.contains(&"glow-p") {
            glowp_bench(&b, &p, &mut rng);
        }
        if which.contains(&"ddh") {
            ddh_bench(&b, &p, &mut rng);
        }
        for (name, v) in [("icy", icy::Variant::Icy), ("icy-n", icy::Variant::IcyN), ("icy-a", icy::Variant::IcyA)] {
            if which.contains(&name) {
                icy_bench(&b, &p, &mut rng, v);
            }
        }
    }
}
