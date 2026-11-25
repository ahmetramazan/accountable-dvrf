//! DDH-DVRF of Galindo et al., over G1 of BLS12-381, as the accountable
//! baseline that keeps the per-party proofs. Keys come from a trusted dealer.

use crate::common::*;
use crate::cp::{self, CpProof};
use blstrs::Scalar;
use rand_core::RngCore;

pub const H: &str = "DDH-H";
pub const HCP: &str = "DDH-CP";
pub const HOUT: &str = "DDH-OUT";

#[derive(Clone)]
pub struct DdhKeys {
    pub params: Params,
    pub pk: G1,
    pub vks: Vec<G1>,
    pub sks: Vec<Scalar>,
}

pub fn setup<R: RngCore>(rng: &mut R, params: Params) -> DdhKeys {
    let (sk, sks) = shamir_deal(rng, params.t, params.n);
    let vks = sks.iter().map(|s| g1_generator() * s).collect();
    DdhKeys { params, pk: g1_generator() * sk, vks, sks }
}

#[derive(Clone, Copy, Debug)]
pub struct Partial {
    pub i: usize,
    pub v: G1,
    pub proof: CpProof,
}

pub fn hash_input(x: &Input) -> G1 {
    hash_to_g1(H, x)
}

pub fn peval<R: RngCore>(rng: &mut R, k: &DdhKeys, i: usize, x: &Input) -> Partial {
    let h = hash_input(x);
    let sk = k.sks[i - 1];
    let v = h * sk;
    let proof = cp::prove(rng, HCP, &g1_generator(), &h, &k.vks[i - 1], &v, &sk);
    Partial { i, v, proof }
}

pub fn pver(vks: &[G1], h: &G1, p: &Partial) -> bool {
    cp::verify(HCP, &g1_generator(), h, &vks[p.i - 1], &p.v, &p.proof)
}

/// The proof is the list of the `t+1` partial evaluations, with their indices.
#[derive(Clone, Debug)]
pub struct DdhProof {
    pub parts: Vec<Partial>,
}

pub fn output_from(parts: &[Partial]) -> [u8; 32] {
    let set: Vec<usize> = parts.iter().map(|p| p.i).collect();
    let lam = lagrange_at_zero(&set);
    let vs: Vec<G1> = parts.iter().map(|p| p.v).collect();
    hash_to_bytes(HOUT, &[&g1_bytes(&g1_msm(&vs, &lam))])
}

pub fn combine(k: &DdhKeys, x: &Input, parts: &[Partial]) -> Option<([u8; 32], DdhProof)> {
    let h = hash_input(x);
    let valid: Vec<Partial> = parts.iter().filter(|p| pver(&k.vks, &h, p)).copied().collect();
    if valid.len() < k.params.t + 1 {
        return None;
    }
    let used = valid[..k.params.t + 1].to_vec();
    Some((output_from(&used), DdhProof { parts: used }))
}

pub fn verify(vks: &[G1], t: usize, x: &Input, y: &[u8; 32], pi: &DdhProof) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    if pi.parts.len() != t + 1 || !pi.parts.iter().all(|p| p.i >= 1 && p.i <= vks.len() && seen.insert(p.i)) {
        return false;
    }
    let h = hash_input(x);
    pi.parts.iter().all(|p| pver(vks, &h, p)) && output_from(&pi.parts) == *y
}

pub fn trace(k: &DdhKeys, x: &Input, y: &[u8; 32], pi: &DdhProof) -> Option<Vec<usize>> {
    verify(&k.vks, k.params.t, x, y, pi).then(|| pi.parts.iter().map(|p| p.i).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn ddh_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let p = Params::honest_majority(7);
        let k = setup(&mut rng, p);
        let x = [1u8; 32];
        let parts: Vec<Partial> = (1..=p.n).map(|i| peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = combine(&k, &x, &parts[3..]).unwrap();
        assert_eq!(trace(&k, &x, &y, &pi), Some(vec![4, 5, 6, 7]));
        let (y2, _) = combine(&k, &x, &parts).unwrap();
        assert_eq!(y, y2);
    }
}
