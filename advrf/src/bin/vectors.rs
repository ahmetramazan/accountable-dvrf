//! Writes test vectors for the on-chain verifiers: one JSON file per scheme
//! and committee size, with the public parameters, an input, the output and
//! the proof of an honest evaluation by the smallest quorum `{1, ..., t+1}`.
//!
//! Usage: `cargo run --release --bin vectors -- <out_dir> [--n 5,10]`

use advrf::common::*;
use advrf::{ddh, glow, icy};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::{Value, json};
use std::path::Path;

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn concat_g1(v: &[G1]) -> String {
    hx(&v.iter().flat_map(g1_bytes).collect::<Vec<u8>>())
}

fn concat_g2(v: &[G2]) -> String {
    hx(&v.iter().flat_map(g2_bytes).collect::<Vec<u8>>())
}

fn write(dir: &Path, name: &str, v: Value) {
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(args.get(1).map(String::as_str).unwrap_or("../vectors")).to_path_buf();
    let ns: Vec<usize> = args
        .iter()
        .position(|a| a == "--n")
        .map(|i| args[i + 1].split(',').map(|v| v.parse().unwrap()).collect())
        .unwrap_or(vec![5, 6, 7, 10, 25, 50, 100]);
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = StdRng::seed_from_u64(42);

    for &n in &ns {
        let p = Params::honest_majority(n);
        let q = p.min_quorum();
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&(n as u64).to_be_bytes());
        x[31] = 0x5a;
        let common = |pk: Value| json!({ "n": n, "t": p.t, "quorum": q.len(), "x": hx(&x), "pk": pk });

        // GLOW-DVRF
        let k = glow::setup(&mut rng, p);
        let parts: Vec<glow::Partial> = q.iter().map(|&i| glow::peval(&mut rng, &k, i, &x)).collect();
        let (y, sigma) = glow::combine(&k, &x, &parts).unwrap();
        assert!(glow::verify(&k.pk, &x, &y, &sigma));
        let mut v = common(json!(hx(&g2_bytes(&k.pk))));
        v["y"] = json!(hx(&y));
        v["sigma"] = json!(hx(&g1_bytes(&sigma)));
        write(&dir, &format!("glow_n{n}"), v);

        // GLOW-A, MSP-pop
        let k = glow::msp_setup(&mut rng, p);
        let parts: Vec<glow::AccPartial> = q.iter().map(|&i| glow::msp_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = glow::msp_combine(&k, &x, &parts).unwrap();
        assert!(glow::msp_trace(&k, &x, &y, &pi).is_some());
        let mut v = common(json!(hx(&g2_bytes(&k.glow.pk))));
        v["ppHash"] = json!(hx(&k.glow.pp_hash));
        v["keys"] = json!(concat_g2(&k.ak));
        v["y"] = json!(hx(&y));
        v["sigma"] = json!(hx(&g1_bytes(&pi.sigma)));
        v["set"] = json!(hx(&pi.set));
        v["s"] = json!(hx(&g1_bytes(&pi.s)));
        write(&dir, &format!("glow_msp_n{n}"), v);

        // GLOW-A, ASM-pop
        let k = glow::asm_setup(&mut rng, p);
        let parts: Vec<glow::AccPartial> = q.iter().map(|&i| glow::asm_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = glow::asm_combine(&k, &x, &parts).unwrap();
        assert!(glow::asm_trace(&k, &x, &y, &pi).is_some());
        let mut v = common(json!(hx(&g2_bytes(&k.msp.glow.pk))));
        v["ppHash"] = json!(hx(&k.msp.glow.pp_hash));
        v["apkHash"] = json!(hx(&k.apk_hash));
        v["yAgg"] = json!(hx(&g2_bytes(&k.y_agg)));
        v["h6"] = json!(concat_g1(&k.h6));
        v["y"] = json!(hx(&y));
        v["sigma"] = json!(hx(&g1_bytes(&pi.sigma)));
        v["set"] = json!(hx(&pi.set));
        v["pks"] = json!(hx(&g2_bytes(&pi.pks)));
        v["s"] = json!(hx(&g1_bytes(&pi.s)));
        write(&dir, &format!("glow_asm_n{n}"), v);

        // DDH-DVRF
        let k = ddh::setup(&mut rng, p);
        let parts: Vec<ddh::Partial> = q.iter().map(|&i| ddh::peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = ddh::combine(&k, &x, &parts).unwrap();
        assert!(ddh::trace(&k, &x, &y, &pi).is_some());
        let mut proof = Vec::new();
        for part in &pi.parts {
            proof.extend_from_slice(&g1_bytes(&part.v));
            proof.extend_from_slice(&scalar_bytes(&part.proof.c));
            proof.extend_from_slice(&scalar_bytes(&part.proof.z));
        }
        let set: Vec<usize> = pi.parts.iter().map(|p| p.i).collect();
        let mut v = common(json!(hx(&g1_bytes(&k.pk))));
        v["vks"] = json!(concat_g1(&k.vks));
        v["y"] = json!(hx(&y));
        v["set"] = json!(hx(&bitmap(&set)));
        v["proof"] = json!(hx(&proof));
        write(&dir, &format!("ddh_n{n}"), v);

        // Icy-DVRF, Icy-N, Icy-A
        for (name, variant) in [("icy", icy::Variant::Icy), ("icy_n", icy::Variant::IcyN), ("icy_a", icy::Variant::IcyA)] {
            let k = icy::setup(&mut rng, p, variant);
            let (y, pi) = icy::evaluate(&mut rng, &k, variant, &x, &q).unwrap();
            assert!(icy::verify(variant, &k.pk, &k.pp_hash, &k.xk, p.t, &x, &y, &pi));
            let mut v = common(json!(hx(&g1_bytes(&k.pk))));
            v["ppHash"] = json!(hx(&k.pp_hash));
            v["y"] = json!(hx(&y));
            v["gamma"] = json!(hx(&g1_bytes(&pi.gamma)));
            v["c"] = json!(hx(&scalar_bytes(&pi.c)));
            v["z"] = json!(hx(&scalar_bytes(&pi.z)));
            v["set"] = json!(hx(&pi.set));
            v["rhat"] = json!(hx(&g1_bytes(&pi.rhat)));
            v["zhat"] = json!(hx(&scalar_bytes(&pi.zhat)));
            v["keys"] = json!(concat_g1(&k.xk));
            write(&dir, &format!("{name}_n{n}"), v);
        }
    }
    eprintln!("wrote vectors for n = {ns:?} to {}", dir.display());
}
