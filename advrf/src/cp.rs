//! Chaum–Pedersen proofs of discrete-log equality in G1, made non-interactive
//! with Fiat–Shamir. The challenge hashes the statement and the commitments.

use crate::common::*;
use blstrs::Scalar;
use rand_core::RngCore;

#[derive(Clone, Copy, Debug)]
pub struct CpProof {
    pub c: Scalar,
    pub z: Scalar,
}

fn challenge(tag: &str, g: &G1, h: &G1, a: &G1, b: &G1, ca: &G1, cb: &G1) -> Scalar {
    hash_to_scalar(
        tag,
        &[
            &g1_bytes(g),
            &g1_bytes(h),
            &g1_bytes(a),
            &g1_bytes(b),
            &g1_bytes(ca),
            &g1_bytes(cb),
        ],
    )
}

/// Proves `log_g a = log_h b = w`.
pub fn prove<R: RngCore>(rng: &mut R, tag: &str, g: &G1, h: &G1, a: &G1, b: &G1, w: &Scalar) -> CpProof {
    let k = random_scalar(rng);
    let ca = g * k;
    let cb = h * k;
    let c = challenge(tag, g, h, a, b, &ca, &cb);
    CpProof { c, z: k + c * w }
}

pub fn verify(tag: &str, g: &G1, h: &G1, a: &G1, b: &G1, p: &CpProof) -> bool {
    let ca = g1_msm(&[*g, *a], &[p.z, -p.c]);
    let cb = g1_msm(&[*h, *b], &[p.z, -p.c]);
    challenge(tag, g, h, a, b, &ca, &cb) == p.c
}
