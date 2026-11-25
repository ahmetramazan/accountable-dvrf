//! GLOW-P: GLOW-DVRF with private accountability, from MSP-pop and
//! Groth–Sahai proofs under SXDH.
//!
//! The combiner commits to the indicator vector of the quorum `S` (on both
//! sides), to the aggregate signature `s` (G1) and to the aggregate key
//! `PK_S` (G2), and proves
//!
//! * (E1) `e(s, g2) * e(h_x, PK_S)^-1 = 1`,
//! * (E2) `PK_S = sum_i beta_i * AK_i`,
//! * (E3) `beta_i (1 - beta'_i) = 0` and `beta_i = beta'_i` for every i,
//! * (E4) `sum_i beta_i = t + 1`.
//!
//! The tracer holds the extraction trapdoor of the binding CRS. Verification
//! batches all equations into one multi-pairing: every 2x2 matrix of pairings
//! is multiplied by `(alpha, 1)` from the left and `(beta, 1)^T` from the
//! right, and every equation by its own random weight; the coefficients come
//! from a Fiat–Shamir hash of the statement and the proof.

use crate::common::*;
use crate::glow::{self, AccPartial, MspKeys};
use blstrs::{G1Affine, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand_core::RngCore;

pub const HFS: &str = "GLOWP-FS";

/// An element of B1 = G1^2.
pub type B1 = [G1; 2];
/// An element of B2 = G2^2.
pub type B2 = [G2; 2];

fn b1_add(a: &B1, b: &B1) -> B1 {
    [a[0] + b[0], a[1] + b[1]]
}
fn b1_mul(a: &B1, s: &Scalar) -> B1 {
    [a[0] * s, a[1] * s]
}
fn b2_add(a: &B2, b: &B2) -> B2 {
    [a[0] + b[0], a[1] + b[1]]
}
fn b2_mul(a: &B2, s: &Scalar) -> B2 {
    [a[0] * s, a[1] * s]
}
fn b1_zero() -> B1 {
    [G1::identity(), G1::identity()]
}
fn b2_zero() -> B2 {
    [G2::identity(), G2::identity()]
}
fn iota1(x: &G1) -> B1 {
    [G1::identity(), *x]
}
fn iota2(y: &G2) -> B2 {
    [G2::identity(), *y]
}

/// Common reference string: `u1, u2` and `u = u2 + (0, g1)` on the G1 side,
/// and `v1, v2, v` on the G2 side.
#[derive(Clone, Debug)]
pub struct Crs {
    pub u1: B1,
    pub u2: B1,
    pub u: B1,
    pub v1: B2,
    pub v2: B2,
    pub v: B2,
}

/// Extraction trapdoor of a binding CRS: `u1 = (g1, a g1)`, `v1 = (g2, b g2)`.
#[derive(Clone, Copy, Debug)]
pub struct Trapdoor {
    pub a: Scalar,
    pub b: Scalar,
}

/// Binding setup, run by the tracer.
pub fn binding_setup<R: RngCore>(rng: &mut R) -> (Crs, Trapdoor) {
    let (g1, g2) = (g1_generator(), g2_generator());
    let (a, t1) = (random_nonzero_scalar(rng), random_nonzero_scalar(rng));
    let (b, t2) = (random_nonzero_scalar(rng), random_nonzero_scalar(rng));
    let u1 = [g1, g1 * a];
    let u2 = b1_mul(&u1, &t1);
    let u = b1_add(&u2, &iota1(&g1));
    let v1 = [g2, g2 * b];
    let v2 = b2_mul(&v1, &t2);
    let v = b2_add(&v2, &iota2(&g2));
    (Crs { u1, u2, u, v1, v2, v }, Trapdoor { a, b })
}

/// A commitment in B1 with its opening: `com = value + r0 u1 + r1 u2`, where
/// `value` is `iota1(X)` for a group element and `x u` for a scalar.
#[derive(Clone, Copy, Debug)]
struct Open1 {
    com: B1,
    value: B1,
    r: [Scalar; 2],
}

#[derive(Clone, Copy, Debug)]
struct Open2 {
    com: B2,
    value: B2,
    r: [Scalar; 2],
}

fn commit_g1<R: RngCore>(rng: &mut R, crs: &Crs, x: &G1) -> Open1 {
    let r = [random_scalar(rng), random_scalar(rng)];
    let value = iota1(x);
    let com = b1_add(&b1_add(&value, &b1_mul(&crs.u1, &r[0])), &b1_mul(&crs.u2, &r[1]));
    Open1 { com, value, r }
}

fn commit_scalar1<R: RngCore>(rng: &mut R, crs: &Crs, x: &Scalar) -> Open1 {
    let r = [random_scalar(rng), Scalar::ZERO];
    let value = b1_mul(&crs.u, x);
    Open1 { com: b1_add(&value, &b1_mul(&crs.u1, &r[0])), value, r }
}

fn commit_g2<R: RngCore>(rng: &mut R, crs: &Crs, y: &G2) -> Open2 {
    let r = [random_scalar(rng), random_scalar(rng)];
    let value = iota2(y);
    let com = b2_add(&b2_add(&value, &b2_mul(&crs.v1, &r[0])), &b2_mul(&crs.v2, &r[1]));
    Open2 { com, value, r }
}

fn commit_scalar2<R: RngCore>(rng: &mut R, crs: &Crs, y: &Scalar) -> Open2 {
    let r = [random_scalar(rng), Scalar::ZERO];
    let value = b2_mul(&crs.v, y);
    Open2 { com: b2_add(&value, &b2_mul(&crs.v1, &r[0])), value, r }
}

/// A GS proof `(pi, theta)` with `pi` in B2^k for the k basis vectors of the
/// G1-side randomness, and `theta` in B1^l for the l basis vectors of the
/// G2-side randomness.
#[derive(Clone, Debug)]
pub struct GsProof {
    pub pi: Vec<B2>,
    pub theta: Vec<B1>,
}

/// A quadratic equation over B1 x B2:
/// `sum_j F(a_j, d_j) + sum_i F(c_i, b_i) + sum_{i,j} gamma_ij F(c_i, d_j) = 0`,
/// where `c` are the G1-side commitments and `d` the G2-side commitments.
struct Equation<'a> {
    c: Vec<&'a Open1>,
    d: Vec<&'a Open2>,
    a: Vec<B1>,
    b: Vec<B2>,
    gamma: Vec<(usize, usize, Scalar)>,
    /// Number of G1-side randomness vectors used (1: u1, 2: u1 and u2).
    k: usize,
    /// Number of G2-side randomness vectors used.
    l: usize,
}

/// Generic GS prover (Groth–Sahai, Sect. 4):
/// `pi = R^T b + R^T Gamma iota2(Y) + R^T Gamma S v - T^T v`,
/// `theta = S^T a + S^T Gamma^T iota1(X) + T u`.
fn prove_eq<R: RngCore>(rng: &mut R, crs: &Crs, eq: &Equation) -> GsProof {
    let ub = [crs.u1, crs.u2];
    let vb = [crs.v1, crs.v2];
    // T is l x k.
    let t: Vec<Vec<Scalar>> = (0..eq.l).map(|_| (0..eq.k).map(|_| random_scalar(&mut *rng)).collect()).collect();
    let mut pi = vec![b2_zero(); eq.k];
    for (kk, p) in pi.iter_mut().enumerate() {
        for (i, ci) in eq.c.iter().enumerate() {
            if ci.r[kk] != Scalar::ZERO {
                *p = b2_add(p, &b2_mul(&eq.b[i], &ci.r[kk]));
            }
        }
        for &(i, j, g) in &eq.gamma {
            let ri = eq.c[i].r[kk] * g;
            // R^T Gamma iota2(Y) and R^T Gamma S v
            *p = b2_add(p, &b2_mul(&eq.d[j].value, &ri));
            for ll in 0..eq.l {
                *p = b2_add(p, &b2_mul(&vb[ll], &(ri * eq.d[j].r[ll])));
            }
        }
        for ll in 0..eq.l {
            *p = b2_add(p, &b2_mul(&vb[ll], &(-t[ll][kk])));
        }
    }
    let mut theta = vec![b1_zero(); eq.l];
    for (ll, th) in theta.iter_mut().enumerate() {
        for (j, dj) in eq.d.iter().enumerate() {
            if dj.r[ll] != Scalar::ZERO {
                *th = b1_add(th, &b1_mul(&eq.a[j], &dj.r[ll]));
            }
        }
        for &(i, j, g) in &eq.gamma {
            *th = b1_add(th, &b1_mul(&eq.c[i].value, &(eq.d[j].r[ll] * g)));
        }
        for kk in 0..eq.k {
            *th = b1_add(th, &b1_mul(&ub[kk], &t[ll][kk]));
        }
    }
    GsProof { pi, theta }
}

/// The proof of GLOW-P.
#[derive(Clone, Debug)]
pub struct GlowpProof {
    pub sigma: G1,
    pub c_s: B1,
    pub c_beta: Vec<B1>,
    pub d_pk: B2,
    pub d_beta: Vec<B2>,
    pub e1: GsProof,
    pub e2: GsProof,
    pub e3a: Vec<GsProof>,
    pub e3b: Vec<GsProof>,
    pub e4: Scalar,
}

impl GlowpProof {
    /// Numbers of G1 and G2 elements and of scalars in the proof.
    pub fn size(&self) -> (usize, usize, usize) {
        let gs = |p: &GsProof| (2 * p.theta.len(), 2 * p.pi.len());
        let mut g1 = 1 + 2 + 2 * self.c_beta.len();
        let mut g2 = 2 + 2 * self.d_beta.len();
        for p in [&self.e1, &self.e2].into_iter().chain(self.e3a.iter()).chain(self.e3b.iter()) {
            let (a, b) = gs(p);
            g1 += a;
            g2 += b;
        }
        (g1, g2, 1)
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let p1 = |o: &mut Vec<u8>, b: &B1| {
            o.extend_from_slice(&g1_bytes(&b[0]));
            o.extend_from_slice(&g1_bytes(&b[1]));
        };
        let p2 = |o: &mut Vec<u8>, b: &B2| {
            o.extend_from_slice(&g2_bytes(&b[0]));
            o.extend_from_slice(&g2_bytes(&b[1]));
        };
        out.extend_from_slice(&g1_bytes(&self.sigma));
        p1(&mut out, &self.c_s);
        self.c_beta.iter().for_each(|c| p1(&mut out, c));
        p2(&mut out, &self.d_pk);
        self.d_beta.iter().for_each(|d| p2(&mut out, d));
        for p in [&self.e1, &self.e2].into_iter().chain(self.e3a.iter()).chain(self.e3b.iter()) {
            p.pi.iter().for_each(|x| p2(&mut out, x));
            p.theta.iter().for_each(|x| p1(&mut out, x));
        }
        out.extend_from_slice(&scalar_bytes(&self.e4));
        out
    }
}

/// Combination: GLOW part, aggregate signature and key, and the GS proof.
/// `parts` are `t+1` contributions that passed `msp_pver`.
pub fn combine_checked<R: RngCore>(
    rng: &mut R,
    k: &MspKeys,
    crs: &Crs,
    x: &Input,
    parts: &[AccPartial],
) -> ([u8; 32], GlowpProof) {
    let n = k.glow.params.n;
    let glow_parts: Vec<glow::Partial> = parts.iter().map(|p| p.glow).collect();
    let (y, sigma) = glow::combine_checked(&glow_parts, k.glow.params.t);
    let set: Vec<usize> = parts.iter().map(|p| p.glow.i).collect();
    let s: G1 = parts.iter().map(|p| p.s).sum();
    let pk_s: G2 = set.iter().map(|&i| k.ak[i - 1]).sum();
    let hx = glow::msp_hx(&k.glow.pp_hash, x);
    let bits: Vec<Scalar> = (1..=n).map(|i| if set.contains(&i) { Scalar::ONE } else { Scalar::ZERO }).collect();

    let os = commit_g1(rng, crs, &s);
    let ob: Vec<Open1> = bits.iter().map(|b| commit_scalar1(rng, crs, b)).collect();
    let opk = commit_g2(rng, crs, &pk_s);
    let ob2: Vec<Open2> = bits.iter().map(|b| commit_scalar2(rng, crs, b)).collect();

    // (E1) F(c_s, iota2(g2)) + F(iota1(-h_x), d_PK) = 0
    let e1 = prove_eq(
        rng,
        crs,
        &Equation {
            c: vec![&os],
            d: vec![&opk],
            a: vec![iota1(&-hx)],
            b: vec![iota2(&g2_generator())],
            gamma: vec![],
            k: 2,
            l: 2,
        },
    );
    // (E2) sum_i F(c_beta_i, iota2(AK_i)) + F(-u, d_PK) = 0
    let e2 = prove_eq(
        rng,
        crs,
        &Equation {
            c: ob.iter().collect(),
            d: vec![&opk],
            a: vec![b1_mul(&crs.u, &-Scalar::ONE)],
            b: k.ak.iter().map(iota2).collect(),
            gamma: vec![],
            k: 1,
            l: 2,
        },
    );
    // (E3a) F(c_beta_i, v) - F(c_beta_i, d_beta'_i) = 0
    // (E3b) F(c_beta_i, v) + F(-u, d_beta'_i) = 0
    let mut e3a = Vec::with_capacity(n);
    let mut e3b = Vec::with_capacity(n);
    for i in 0..n {
        e3a.push(prove_eq(
            rng,
            crs,
            &Equation {
                c: vec![&ob[i]],
                d: vec![&ob2[i]],
                a: vec![b1_zero()],
                b: vec![crs.v],
                gamma: vec![(0, 0, -Scalar::ONE)],
                k: 1,
                l: 1,
            },
        ));
        e3b.push(prove_eq(
            rng,
            crs,
            &Equation {
                c: vec![&ob[i]],
                d: vec![&ob2[i]],
                a: vec![b1_mul(&crs.u, &-Scalar::ONE)],
                b: vec![crs.v],
                gamma: vec![],
                k: 1,
                l: 1,
            },
        ));
    }
    // (E4) sum_i c_beta_i - (t+1) u = (sum_i r_i) u1
    let e4: Scalar = ob.iter().map(|o| o.r[0]).sum();

    let proof = GlowpProof {
        sigma,
        c_s: os.com,
        c_beta: ob.iter().map(|o| o.com).collect(),
        d_pk: opk.com,
        d_beta: ob2.iter().map(|o| o.com).collect(),
        e1,
        e2,
        e3a,
        e3b,
        e4,
    };
    (y, proof)
}

/// Collects the pairings of the batched check, merging the terms that share
/// a G2 element known to the verifier.
struct Batch {
    shared: Vec<(G1, G2)>,
    other: Vec<(G1, G2)>,
}

impl Batch {
    fn shared(&mut self, slot: usize, p: G1) {
        self.shared[slot].0 += p;
    }
    fn other(&mut self, p: G1, q: G2) {
        self.other.push((p, q));
    }
    fn check(self) -> bool {
        use pairing::{MillerLoopResult, MultiMillerLoop};
        let terms: Vec<(G1, G2)> = self.shared.into_iter().chain(self.other).collect();
        let a: Vec<G1Affine> = terms.iter().map(|(p, _)| p.to_affine()).collect();
        let b: Vec<blstrs::G2Prepared> = terms.iter().map(|(_, q)| q.to_affine().into()).collect();
        let refs: Vec<(&G1Affine, &blstrs::G2Prepared)> = a.iter().zip(b.iter()).collect();
        bool::from(blstrs::Bls12::multi_miller_loop(&refs).final_exponentiation().is_identity())
    }
}

/// Verification: GLOW part and all GS equations in one batched multi-pairing.
pub fn verify(
    pk: &G2,
    pp_hash: &[u8; 32],
    ak: &[G2],
    t: usize,
    crs: &Crs,
    x: &Input,
    y: &[u8; 32],
    pi: &GlowpProof,
) -> bool {
    let n = ak.len();
    if pi.c_beta.len() != n || pi.d_beta.len() != n || pi.e3a.len() != n || pi.e3b.len() != n {
        return false;
    }
    let shapes_ok = pi.e1.pi.len() == 2
        && pi.e1.theta.len() == 2
        && pi.e2.pi.len() == 1
        && pi.e2.theta.len() == 2
        && pi.e3a.iter().chain(pi.e3b.iter()).all(|p| p.pi.len() == 1 && p.theta.len() == 1);
    if !shapes_ok || glow::output(&pi.sigma) != *y {
        return false;
    }
    // (E4) is linear and checked directly.
    let sum_c = pi.c_beta.iter().fold(b1_zero(), |acc, c| b1_add(&acc, c));
    let rhs = b1_add(&b1_mul(&crs.u, &Scalar::from((t + 1) as u64)), &b1_mul(&crs.u1, &pi.e4));
    if sum_c != rhs {
        return false;
    }

    // Fiat–Shamir coefficients: alpha, beta and one weight per equation
    // (GLOW, E1, E2, and 2n for E3).
    let digest = keccak(&[pp_hash, x, y, &pi.bytes()]);
    let coef = |j: u64| hash_to_scalar(HFS, &[&digest, &j.to_be_bytes()]);
    let (alpha, beta) = (coef(0), coef(1));
    let w = |j: usize| coef(2 + j as u64);
    let c1 = |b: &B1| b[0] * alpha + b[1];
    let c2 = |b: &B2| b[0] * beta + b[1];

    let g2 = g2_generator();
    let (u1h, u2h, uh) = (c1(&crs.u1), c1(&crs.u2), c1(&crs.u));
    let (v1h, v2h, vh) = (c2(&crs.v1), c2(&crs.v2), c2(&crs.v));
    // Shared G2 elements: 0: g2, 1: v1^, 2: v2^, 3: v^, 4..4+n: AK_i (as iota2,
    // compressed to AK_i), 4+n: pk.
    let mut shared = vec![(G1::identity(), g2), (G1::identity(), v1h), (G1::identity(), v2h), (G1::identity(), vh)];
    shared.extend(ak.iter().map(|a| (G1::identity(), *a)));
    shared.push((G1::identity(), *pk));
    let mut bt = Batch { shared, other: Vec::with_capacity(4 + 2 * n) };
    let s_pk = 4 + n;

    // GLOW: e(sigma, g2) = e(H1(x), pk)
    let w0 = w(0);
    bt.shared(0, pi.sigma * w0);
    bt.shared(s_pk, -(glow::h1(x) * w0));

    // Compressed G2 commitments.
    let dpk = c2(&pi.d_pk);
    let db: Vec<G2> = pi.d_beta.iter().map(c2).collect();
    let cs = c1(&pi.c_s);
    let cb: Vec<G1> = pi.c_beta.iter().map(c1).collect();
    let hx = glow::msp_hx(pp_hash, x);

    // (E1) e(cs, g2) + e(-h_x, dPK) - e(u1^, pi_0) - e(u2^, pi_1) - e(theta_0, v1^) - e(theta_1, v2^)
    // iota2(g2) compresses to g2 and iota1(-h_x) to -h_x.
    let w1 = w(1);
    bt.shared(0, cs * w1);
    let mut on_dpk = -(hx * w1);
    bt.other(-(u1h * w1), c2(&pi.e1.pi[0]));
    bt.other(-(u2h * w1), c2(&pi.e1.pi[1]));
    bt.shared(1, -(c1(&pi.e1.theta[0]) * w1));
    bt.shared(2, -(c1(&pi.e1.theta[1]) * w1));

    // (E2) sum_i e(cb_i, AK_i) + e(-u^, dPK) - e(u1^, pi_0) - e(theta_0, v1^) - e(theta_1, v2^)
    let w2 = w(2);
    for (i, c) in cb.iter().enumerate() {
        bt.shared(4 + i, c * w2);
    }
    on_dpk += -(uh * w2);
    bt.other(-(u1h * w2), c2(&pi.e2.pi[0]));
    bt.shared(1, -(c1(&pi.e2.theta[0]) * w2));
    bt.shared(2, -(c1(&pi.e2.theta[1]) * w2));
    bt.other(on_dpk, dpk);

    // (E3a) e(cb_i, v^) - e(cb_i, db_i) - e(u1^, pi) - e(theta, v1^)
    // (E3b) e(cb_i, v^) + e(-u^, db_i) - e(u1^, pi) - e(theta, v1^)
    let mut on_u1 = Vec::with_capacity(2 * n);
    for i in 0..n {
        let (wa, wb) = (w(3 + 2 * i), w(4 + 2 * i));
        bt.shared(3, cb[i] * (wa + wb));
        bt.other(-(cb[i] * wa) - uh * wb, db[i]);
        on_u1.push((wa, c2(&pi.e3a[i].pi[0])));
        on_u1.push((wb, c2(&pi.e3b[i].pi[0])));
        bt.shared(1, -(c1(&pi.e3a[i].theta[0]) * wa) - c1(&pi.e3b[i].theta[0]) * wb);
    }
    // sum_j w_j e(u1^, pi_j) = e(u1^, sum_j w_j pi_j): one pairing.
    let pis: Vec<G2> = on_u1.iter().map(|(_, p)| *p).collect();
    let ws: Vec<Scalar> = on_u1.iter().map(|(w, _)| *w).collect();
    bt.other(-u1h, G2::multi_exp(&pis, &ws));

    bt.check()
}

/// Tracing with the extraction trapdoor: returns `(S, omega = s)` if the
/// proof verifies.
pub fn trace(
    td: &Trapdoor,
    k: &MspKeys,
    crs: &Crs,
    x: &Input,
    y: &[u8; 32],
    pi: &GlowpProof,
) -> Option<(Vec<usize>, G1)> {
    if !verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, k.glow.params.t, crs, x, y, pi) {
        return None;
    }
    let ext = |c: &B1| c[1] - c[0] * td.a;
    let g1 = g1_generator();
    let set: Vec<usize> = pi.c_beta.iter().enumerate().filter(|(_, c)| ext(c) == g1).map(|(i, _)| i + 1).collect();
    Some((set, ext(&pi.c_s)))
}

/// Public check of a trace: `|S| = t+1` and `e(omega, g2) = e(h_x, sum_{i in S} AK_i)`.
pub fn judge(k: &MspKeys, x: &Input, set: &[usize], omega: &G1) -> bool {
    if set.len() != k.glow.params.t + 1 || set.iter().any(|&i| i == 0 || i > k.ak.len()) {
        return false;
    }
    let pks: G2 = set.iter().map(|&i| k.ak[i - 1]).sum();
    pairing_check(&[(*omega, -g2_generator()), (glow::msp_hx(&k.glow.pp_hash, x), pks)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn glowp_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(31);
        let p = Params::honest_majority(7);
        let k = glow::msp_setup(&mut rng, p);
        let (crs, td) = binding_setup(&mut rng);
        let x = [4u8; 32];
        let q = [2usize, 3, 5, 7];
        let parts: Vec<AccPartial> = q.iter().map(|&i| glow::msp_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = combine_checked(&mut rng, &k, &crs, &x, &parts);
        assert!(verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &pi));
        assert_eq!(pi.size(), (11 + 6 * p.n, 8 + 6 * p.n, 1));
        let (set, omega) = trace(&td, &k, &crs, &x, &y, &pi).unwrap();
        assert_eq!(set, q.to_vec());
        assert!(judge(&k, &x, &set, &omega));
        assert!(!judge(&k, &x, &[1, 3, 5, 7], &omega));

        // Tampering with any part of the proof breaks verification.
        let mut bad = pi.clone();
        bad.c_beta.swap(0, 1);
        assert!(!verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &bad));
        let mut bad = pi.clone();
        bad.e1.theta[0][1] += g1_generator();
        assert!(!verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &bad));
        let mut bad = pi.clone();
        bad.e3a[3].pi[0][0] += g2_generator();
        assert!(!verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &bad));
        assert!(!verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &[5u8; 32], &y, &pi));
    }

    #[test]
    fn glowp_rejects_wrong_quorum_size() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(32);
        let p = Params::honest_majority(5);
        let k = glow::msp_setup(&mut rng, p);
        let (crs, _) = binding_setup(&mut rng);
        let x = [4u8; 32];
        // A quorum of t+2 parties: the honest prover's proof fails (E4).
        let parts: Vec<AccPartial> = (1..=4).map(|i| glow::msp_peval(&mut rng, &k, i, &x)).collect();
        let (y, pi) = combine_checked(&mut rng, &k, &crs, &x, &parts);
        assert!(!verify(&k.glow.pk, &k.glow.pp_hash, &k.ak, p.t, &crs, &x, &y, &pi));
    }
}
