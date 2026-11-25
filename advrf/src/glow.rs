//! GLOW-DVRF and its accountable instances GLOW-A with MSP-pop (main scheme)
//! and with ASM-pop (variant).
//!
//! The DKG is replaced by a trusted dealer that outputs the same keys. The DKG
//! is a one-time setup and is not part of the measured evaluation costs.

use crate::common::*;
use crate::cp::{self, CpProof};
use blstrs::Scalar;
use rand_core::RngCore;

// Random oracles of GLOW-DVRF.
pub const H1: &str = "GLOW-H1";
pub const H2: &str = "GLOW-H2";
pub const H3: &str = "GLOW-H3";
// Random oracles of the multisignatures.
pub const H4: &str = "GLOWA-H4";
pub const H5: &str = "GLOWA-H5";
pub const H6: &str = "GLOWA-H6";
pub const H7: &str = "GLOWA-H7";
pub const HRHO: &str = "GLOWA-RHO";
pub const PP: &str = "PP";

// ---------------------------------------------------------------------------
// GLOW-DVRF
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GlowKeys {
    pub params: Params,
    pub pk: G2,
    pub vks: Vec<G1>,
    pub sks: Vec<Scalar>,
    /// Digest of `(pk, vk_1, ..., vk_n)`, used for `m_x = <pk, {vk_i}, x>`.
    pub pp_hash: [u8; 32],
}

pub fn pp_hash(pk: &G2, vks: &[G1]) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = vec![g2_bytes(pk).to_vec()];
    parts.extend(vks.iter().map(|v| g1_bytes(v).to_vec()));
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    hash_to_bytes(PP, &refs)
}

pub fn setup<R: RngCore>(rng: &mut R, params: Params) -> GlowKeys {
    let (sk, sks) = shamir_deal(rng, params.t, params.n);
    let pk = g2_generator() * sk;
    let vks: Vec<G1> = sks.iter().map(|s| g1_generator() * s).collect();
    let pp_hash = pp_hash(&pk, &vks);
    GlowKeys { params, pk, vks, sks, pp_hash }
}

#[derive(Clone, Copy, Debug)]
pub struct Partial {
    pub i: usize,
    pub v: G1,
    pub proof: CpProof,
}

pub fn h1(x: &Input) -> G1 {
    hash_to_g1(H1, x)
}

pub fn output(sigma: &G1) -> [u8; 32] {
    hash_to_bytes(H2, &[&g1_bytes(sigma)])
}

pub fn peval<R: RngCore>(rng: &mut R, k: &GlowKeys, i: usize, x: &Input) -> Partial {
    let h = h1(x);
    let sk = k.sks[i - 1];
    let v = h * sk;
    let proof = cp::prove(rng, H3, &g1_generator(), &h, &k.vks[i - 1], &v, &sk);
    Partial { i, v, proof }
}

pub fn pver(k: &GlowKeys, x: &Input, p: &Partial) -> bool {
    cp::verify(H3, &g1_generator(), &h1(x), &k.vks[p.i - 1], &p.v, &p.proof)
}

/// Combines `t+1` partial evaluations that already passed `pver`.
pub fn combine_checked(parts: &[Partial], t: usize) -> ([u8; 32], G1) {
    let used = &parts[..t + 1];
    let set: Vec<usize> = used.iter().map(|p| p.i).collect();
    let lam = lagrange_at_zero(&set);
    let vs: Vec<G1> = used.iter().map(|p| p.v).collect();
    let sigma = g1_msm(&vs, &lam);
    (output(&sigma), sigma)
}

pub fn combine(k: &GlowKeys, x: &Input, parts: &[Partial]) -> Option<([u8; 32], G1)> {
    let valid: Vec<Partial> = parts.iter().filter(|p| pver(k, x, p)).copied().collect();
    if valid.len() < k.params.t + 1 {
        return None;
    }
    Some(combine_checked(&valid, k.params.t))
}

pub fn verify(pk: &G2, x: &Input, y: &[u8; 32], sigma: &G1) -> bool {
    output(sigma) == *y && pairing_check(&[(*sigma, -g2_generator()), (h1(x), *pk)])
}

// ---------------------------------------------------------------------------
// GLOW-A with MSP-pop
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MspKeys {
    pub glow: GlowKeys,
    pub a: Vec<Scalar>,
    pub ak: Vec<G2>,
    pub pop: Vec<G1>,
}

/// Key generation of one party: `(a_i, AK_i, pop_i)`.
pub fn msp_keygen<R: RngCore>(rng: &mut R) -> (Scalar, G2, G1) {
    let a = random_scalar(rng);
    let ak = g2_generator() * a;
    let pop = hash_to_g1(H7, &g2_bytes(&ak)) * a;
    (a, ak, pop)
}

/// Check of a proof of possession, done by every party once at setup.
pub fn pop_verify(ak: &G2, pop: &G1) -> bool {
    pairing_check(&[(*pop, -g2_generator()), (hash_to_g1(H7, &g2_bytes(ak)), *ak)])
}

pub fn msp_setup<R: RngCore>(rng: &mut R, params: Params) -> MspKeys {
    let glow = setup(rng, params);
    let (mut a, mut ak, mut pop) = (vec![], vec![], vec![]);
    for _ in 0..params.n {
        let (ai, aki, popi) = msp_keygen(rng);
        a.push(ai);
        ak.push(aki);
        pop.push(popi);
    }
    MspKeys { glow, a, ak, pop }
}

/// `m_x = <pk, {vk_i}, x>`, encoded as `pp_hash || x`.
pub fn m_x(pp_hash: &[u8; 32], x: &Input) -> [u8; 64] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(pp_hash);
    m[32..].copy_from_slice(x);
    m
}

pub fn msp_hx(pp_hash: &[u8; 32], x: &Input) -> G1 {
    hash_to_g1(H4, &m_x(pp_hash, x))
}

#[derive(Clone, Copy, Debug)]
pub struct AccPartial {
    pub glow: Partial,
    pub s: G1,
}

pub fn msp_peval<R: RngCore>(rng: &mut R, k: &MspKeys, i: usize, x: &Input) -> AccPartial {
    let glow = peval(rng, &k.glow, i, x);
    let s = msp_hx(&k.glow.pp_hash, x) * k.a[i - 1];
    AccPartial { glow, s }
}

pub fn msp_pver(k: &MspKeys, x: &Input, p: &AccPartial) -> bool {
    let hx = msp_hx(&k.glow.pp_hash, x);
    pver(&k.glow, x, &p.glow) && pairing_check(&[(p.s, -g2_generator()), (hx, k.ak[p.glow.i - 1])])
}

#[derive(Clone, Debug)]
pub struct MspProof {
    pub sigma: G1,
    pub set: [u8; 32],
    pub s: G1,
}

/// Combines partial evaluations that already passed `msp_pver`.
pub fn msp_combine_checked(k: &MspKeys, parts: &[AccPartial]) -> ([u8; 32], MspProof) {
    let glow_parts: Vec<Partial> = parts.iter().map(|p| p.glow).collect();
    let (y, sigma) = combine_checked(&glow_parts, k.glow.params.t);
    let set: Vec<usize> = parts.iter().map(|p| p.glow.i).collect();
    let s = parts.iter().map(|p| p.s).sum();
    (y, MspProof { sigma, set: bitmap(&set), s })
}

pub fn msp_combine(k: &MspKeys, x: &Input, parts: &[AccPartial]) -> Option<([u8; 32], MspProof)> {
    let valid: Vec<AccPartial> = parts.iter().filter(|p| msp_pver(k, x, p)).copied().collect();
    if valid.len() < k.glow.params.t + 1 {
        return None;
    }
    Some(msp_combine_checked(k, &valid))
}

pub fn msp_rho(pp_hash: &[u8; 32], x: &Input, y: &[u8; 32], pi: &MspProof) -> Scalar {
    hash_to_scalar(HRHO, &[pp_hash, x, y, &g1_bytes(&pi.sigma), &pi.set, &g1_bytes(&pi.s)])
}

/// Verification with the batched pairing equation (three pairings):
/// `e(sigma + rho*s, -g2) * e(H1(x), pk) * e(rho*h_x, PK_S) = 1`.
pub fn msp_verify(
    pk: &G2,
    pp_hash: &[u8; 32],
    ak: &[G2],
    t: usize,
    x: &Input,
    y: &[u8; 32],
    pi: &MspProof,
) -> bool {
    let set = bitmap_to_set(&pi.set);
    if set.len() < t + 1 || set.iter().any(|&i| i > ak.len()) || output(&pi.sigma) != *y {
        return false;
    }
    let rho = msp_rho(pp_hash, x, y, pi);
    let pks: G2 = set.iter().map(|&i| ak[i - 1]).sum();
    pairing_check(&[
        (pi.sigma + pi.s * rho, -g2_generator()),
        (h1(x), *pk),
        (msp_hx(pp_hash, x) * rho, pks),
    ])
}

/// Trace: the signer set, if the proof verifies.
pub fn msp_trace(k: &MspKeys, x: &Input, y: &[u8; 32], pi: &MspProof) -> Option<Vec<usize>> {
    msp_verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, k.glow.params.t, x, y, pi).then(|| bitmap_to_set(&pi.set))
}

// ---------------------------------------------------------------------------
// GLOW-A with ASM-pop
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AsmKeys {
    pub msp: MspKeys,
    /// `apk = (Y, kappa)`.
    pub y_agg: G2,
    pub kappa: Scalar,
    /// Digest of `apk`, used as the domain of `H4` and `H6`.
    pub apk_hash: [u8; 32],
    /// Membership keys `mk_i`.
    pub mk: Vec<G1>,
    /// `H6(apk, i)`, which a verifier may store or receive in calldata.
    pub h6: Vec<G1>,
}

pub fn asm_apk(ak: &[G2]) -> (G2, Scalar, [u8; 32]) {
    let y_agg: G2 = ak.iter().sum();
    let parts: Vec<Vec<u8>> = ak.iter().map(|a| g2_bytes(a).to_vec()).collect();
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let kappa = hash_to_scalar(H5, &refs);
    let apk_hash = keccak(&[&g2_bytes(&y_agg), &scalar_bytes(&kappa)]);
    (y_agg, kappa, apk_hash)
}

pub fn asm_h6(apk_hash: &[u8; 32], i: usize) -> G1 {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(apk_hash);
    m[56..].copy_from_slice(&(i as u64).to_be_bytes());
    hash_to_g1(H6, &m)
}

/// Group setup message `mu_{j,i} = H6(apk, j)^{a_i}` from party `i` to `j`.
pub fn asm_mu(apk_hash: &[u8; 32], j: usize, a_i: &Scalar) -> G1 {
    asm_h6(apk_hash, j) * a_i
}

pub fn asm_setup<R: RngCore>(rng: &mut R, params: Params) -> AsmKeys {
    let msp = msp_setup(rng, params);
    let (y_agg, kappa, apk_hash) = asm_apk(&msp.ak);
    let h6: Vec<G1> = (1..=params.n).map(|j| asm_h6(&apk_hash, j)).collect();
    let mk: Vec<G1> = (0..params.n)
        .map(|j| msp.a.iter().map(|a| h6[j] * a).sum())
        .collect();
    AsmKeys { msp, y_agg, kappa, apk_hash, mk, h6 }
}

pub fn asm_hx(apk_hash: &[u8; 32], pp_hash: &[u8; 32], x: &Input) -> G1 {
    let mut m = [0u8; 96];
    m[..32].copy_from_slice(apk_hash);
    m[32..].copy_from_slice(&m_x(pp_hash, x));
    hash_to_g1(H4, &m)
}

pub fn asm_peval<R: RngCore>(rng: &mut R, k: &AsmKeys, i: usize, x: &Input) -> AccPartial {
    let glow = peval(rng, &k.msp.glow, i, x);
    let s = asm_hx(&k.apk_hash, &k.msp.glow.pp_hash, x) * k.msp.a[i - 1] + k.mk[i - 1];
    AccPartial { glow, s }
}

pub fn asm_pver(k: &AsmKeys, x: &Input, p: &AccPartial) -> bool {
    let i = p.glow.i;
    let hx = asm_hx(&k.apk_hash, &k.msp.glow.pp_hash, x);
    pver(&k.msp.glow, x, &p.glow)
        && pairing_check(&[(p.s, -g2_generator()), (hx, k.msp.ak[i - 1]), (k.h6[i - 1], k.y_agg)])
}

#[derive(Clone, Debug)]
pub struct AsmProof {
    pub sigma: G1,
    pub set: [u8; 32],
    pub pks: G2,
    pub s: G1,
}

pub fn asm_combine_checked(k: &AsmKeys, parts: &[AccPartial]) -> ([u8; 32], AsmProof) {
    let (y, msp) = msp_combine_checked(&k.msp, parts);
    let pks = parts.iter().map(|p| k.msp.ak[p.glow.i - 1]).sum();
    (y, AsmProof { sigma: msp.sigma, set: msp.set, pks, s: msp.s })
}

pub fn asm_combine(k: &AsmKeys, x: &Input, parts: &[AccPartial]) -> Option<([u8; 32], AsmProof)> {
    let valid: Vec<AccPartial> = parts.iter().filter(|p| asm_pver(k, x, p)).copied().collect();
    if valid.len() < k.msp.glow.params.t + 1 {
        return None;
    }
    Some(asm_combine_checked(k, &valid))
}

pub fn asm_rho(pp_hash: &[u8; 32], x: &Input, y: &[u8; 32], pi: &AsmProof) -> Scalar {
    hash_to_scalar(
        HRHO,
        &[pp_hash, x, y, &g1_bytes(&pi.sigma), &pi.set, &g2_bytes(&pi.pks), &g1_bytes(&pi.s)],
    )
}

/// Verification with four pairings. `h6` holds `H6(apk, i)` for all `i`.
#[allow(clippy::too_many_arguments)]
pub fn asm_verify(
    pk: &G2,
    pp_hash: &[u8; 32],
    apk_hash: &[u8; 32],
    y_agg: &G2,
    h6: &[G1],
    t: usize,
    x: &Input,
    y: &[u8; 32],
    pi: &AsmProof,
) -> bool {
    let set = bitmap_to_set(&pi.set);
    if set.len() < t + 1 || set.iter().any(|&i| i > h6.len()) || output(&pi.sigma) != *y {
        return false;
    }
    let rho = asm_rho(pp_hash, x, y, pi);
    let hsum: G1 = set.iter().map(|&i| h6[i - 1]).sum();
    pairing_check(&[
        (pi.sigma + pi.s * rho, -g2_generator()),
        (h1(x), *pk),
        (asm_hx(apk_hash, pp_hash, x) * rho, pi.pks),
        (hsum * rho, *y_agg),
    ])
}

pub fn asm_trace(k: &AsmKeys, x: &Input, y: &[u8; 32], pi: &AsmProof) -> Option<Vec<usize>> {
    let g = &k.msp.glow;
    asm_verify(&g.pk, &g.pp_hash, &k.apk_hash, &k.y_agg, &k.h6, g.params.t, x, y, pi)
        .then(|| bitmap_to_set(&pi.set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn glow_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let p = Params::honest_majority(7);
        let k = setup(&mut rng, p);
        let x = [3u8; 32];
        let parts: Vec<Partial> = (1..=p.n).map(|i| peval(&mut rng, &k, i, &x)).collect();
        let (y, sigma) = combine(&k, &x, &parts[2..]).unwrap();
        assert!(verify(&k.pk, &x, &y, &sigma));
        let (y2, _) = combine(&k, &x, &parts[..4]).unwrap();
        assert_eq!(y, y2);
    }

    #[test]
    fn msp_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(8);
        let p = Params::honest_majority(10);
        let k = msp_setup(&mut rng, p);
        assert!(k.ak.iter().zip(&k.pop).all(|(a, b)| pop_verify(a, b)));
        let x = [5u8; 32];
        let q = [2usize, 4, 6, 8, 9];
        let parts: Vec<AccPartial> = q.iter().map(|&i| msp_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = msp_combine(&k, &x, &parts).unwrap();
        assert_eq!(msp_trace(&k, &x, &y, &pi), Some(q.to_vec()));
        let mut bad = pi.clone();
        bad.set = bitmap(&[1, 4, 6, 8, 9]);
        assert!(msp_trace(&k, &x, &y, &bad).is_none());
    }

    #[test]
    fn asm_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let p = Params::honest_majority(6);
        let k = asm_setup(&mut rng, p);
        let x = [6u8; 32];
        let q = [1usize, 3, 6];
        let parts: Vec<AccPartial> = q.iter().map(|&i| asm_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = asm_combine(&k, &x, &parts).unwrap();
        assert_eq!(asm_trace(&k, &x, &y, &pi), Some(q.to_vec()));
        let mut bad = pi.clone();
        bad.set = bitmap(&[1, 2, 6]);
        assert!(asm_trace(&k, &x, &y, &bad).is_none());
    }
}
