//! Icy-DVRF and its accountable instances Icy-N (native, quorum in the
//! challenge) and Icy-A (Icy-DVRF' + MuSig2 with nu = 2), over G1 of
//! BLS12-381. Keys come from a trusted dealer, as in Icy-N; for Icy-DVRF and
//! Icy-A this replaces the FROST DKG, which is a one-time setup.
//!
//! An evaluation has two rounds after preprocessing. In round 1 each party of
//! the quorum returns its evaluation share and auxiliary values (and, in Icy-A,
//! its MuSig2 response). In round 2 it returns its T-DLEQ response.

use crate::common::*;
use crate::cp::{self, CpProof};
use blstrs::Scalar;
use rand_core::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Icy-DVRF, not accountable.
    Icy,
    /// Icy-N: native accountability, `|S| = t+1`.
    IcyN,
    /// Icy-A: Icy-DVRF' + MuSig2, `|S| >= t+1`.
    IcyA,
}

impl Variant {
    fn tag(&self, role: &str) -> String {
        let v = match self {
            Variant::Icy => "ICY",
            // Icy-A uses the T-DLEQ part of Icy-N.
            Variant::IcyN | Variant::IcyA => "ICYN",
        };
        format!("{v}-{role}")
    }

    pub fn name(&self) -> &'static str {
        match self {
            Variant::Icy => "Icy-DVRF",
            Variant::IcyN => "Icy-N",
            Variant::IcyA => "Icy-A",
        }
    }
}

pub const H1: &str = "ICY-H1";
pub const H3: &str = "ICY-H3";
pub const HAGG: &str = "MUSIG2-AGG";
pub const HNON: &str = "MUSIG2-NON";
pub const HSIG: &str = "MUSIG2-SIG";
pub const PP: &str = "PP";

#[derive(Clone)]
pub struct IcyKeys {
    pub params: Params,
    pub pk: G1,
    pub vks: Vec<G1>,
    pub sks: Vec<Scalar>,
    pub pp_hash: [u8; 32],
    /// MuSig2 keys of Icy-A.
    pub a: Vec<Scalar>,
    pub xk: Vec<G1>,
}

pub fn pp_hash(pk: &G1, vks: &[G1]) -> [u8; 32] {
    let mut parts: Vec<Vec<u8>> = vec![g1_bytes(pk).to_vec()];
    parts.extend(vks.iter().map(|v| g1_bytes(v).to_vec()));
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    hash_to_bytes(PP, &refs)
}

pub fn setup<R: RngCore>(rng: &mut R, params: Params, variant: Variant) -> IcyKeys {
    let (sk, sks) = shamir_deal(rng, params.t, params.n);
    let pk = g1_generator() * sk;
    let vks: Vec<G1> = sks.iter().map(|s| g1_generator() * s).collect();
    let pp_hash = pp_hash(&pk, &vks);
    let (mut a, mut xk) = (vec![], vec![]);
    if variant == Variant::IcyA {
        for _ in 0..params.n {
            let ai = random_scalar(rng);
            a.push(ai);
            xk.push(g1_generator() * ai);
        }
    }
    IcyKeys { params, pk, vks, sks, pp_hash, a, xk }
}

/// A single-use preprocessing token with its secret nonces.
#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub d: Scalar,
    pub e: Scalar,
    pub r1: Scalar,
    pub r2: Scalar,
    pub public: TokenPub,
}

#[derive(Clone, Copy, Debug)]
pub struct TokenPub {
    pub d: G1,
    pub e: G1,
    /// MuSig2 nonce commitments (Icy-A only).
    pub r1: G1,
    pub r2: G1,
}

pub fn preprocess<R: RngCore>(rng: &mut R, variant: Variant) -> Token {
    let d = random_nonzero_scalar(rng);
    let e = random_nonzero_scalar(rng);
    let g = g1_generator();
    let (r1, r2, pr1, pr2) = if variant == Variant::IcyA {
        let r1 = random_scalar(rng);
        let r2 = random_scalar(rng);
        (r1, r2, g * r1, g * r2)
    } else {
        (Scalar::from(0u64), Scalar::from(0u64), <G1 as group::Group>::identity(), <G1 as group::Group>::identity())
    };
    Token { d, e, r1, r2, public: TokenPub { d: g * d, e: g * e, r1: pr1, r2: pr2 } }
}

/// The request of the combiner: input, ordered quorum and the quorum's tokens.
#[derive(Clone, Debug)]
pub struct Request {
    pub x: Input,
    pub set: Vec<usize>,
    pub tokens: Vec<TokenPub>,
}

#[derive(Clone, Copy, Debug)]
pub struct Round1 {
    pub i: usize,
    pub gamma: G1,
    pub pi: CpProof,
    pub dbar: G1,
    pub ebar: G1,
    /// Proofs that `(D, Dbar)` and `(E, Ebar)` share the exponent (Icy-N, Icy-A).
    pub pibar: Option<(CpProof, CpProof)>,
    /// MuSig2 response (Icy-A).
    pub zhat: Option<Scalar>,
}

pub fn h1(x: &Input) -> G1 {
    hash_to_g1(H1, x)
}

/// The MuSig2 context of a request: key-aggregation coefficients, aggregate
/// key, nonce coefficient, aggregate nonce and challenge.
#[derive(Clone, Debug)]
pub struct MusigCtx {
    pub mu: Vec<Scalar>,
    pub x_agg: G1,
    pub b: Scalar,
    pub rhat: G1,
    pub chat: Scalar,
}

pub fn musig_keys_hash(keys: &[G1]) -> [u8; 32] {
    let parts: Vec<Vec<u8>> = keys.iter().map(|k| g1_bytes(k).to_vec()).collect();
    let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    keccak(&refs)
}

pub fn musig_mu(l: &[u8; 32], key: &G1) -> Scalar {
    hash_to_scalar(HAGG, &[l, &g1_bytes(key)])
}

pub fn musig_aggregate(keys: &[G1]) -> (Vec<Scalar>, G1) {
    let l = musig_keys_hash(keys);
    let mu: Vec<Scalar> = keys.iter().map(|k| musig_mu(&l, k)).collect();
    let x_agg = g1_msm(keys, &mu);
    (mu, x_agg)
}

pub fn musig_challenge(x_agg: &G1, rhat: &G1, m: &[u8]) -> Scalar {
    hash_to_scalar(HSIG, &[&g1_bytes(x_agg), &g1_bytes(rhat), m])
}

pub fn m_x(pp_hash: &[u8; 32], x: &Input) -> [u8; 64] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(pp_hash);
    m[32..].copy_from_slice(x);
    m
}

pub fn musig_ctx(k: &IcyKeys, req: &Request) -> MusigCtx {
    let keys: Vec<G1> = req.set.iter().map(|&i| k.xk[i - 1]).collect();
    let (mu, x_agg) = musig_aggregate(&keys);
    let r1: G1 = req.tokens.iter().map(|t| t.r1).sum();
    let r2: G1 = req.tokens.iter().map(|t| t.r2).sum();
    let m = m_x(&k.pp_hash, &req.x);
    let b = hash_to_scalar(HNON, &[&g1_bytes(&x_agg), &g1_bytes(&r1), &g1_bytes(&r2), &m]);
    let rhat = r1 + r2 * b;
    let chat = musig_challenge(&x_agg, &rhat, &m);
    MusigCtx { mu, x_agg, b, rhat, chat }
}

fn check_request(k: &IcyKeys, variant: Variant, req: &Request) -> bool {
    let s = req.set.len();
    let size_ok = match variant {
        Variant::IcyN => s == k.params.t + 1,
        _ => s >= k.params.t + 1,
    };
    size_ok && req.tokens.len() == s && req.set.windows(2).all(|w| w[0] < w[1])
}

/// Round 1 of party `i`. The caller is responsible for never reusing a token.
pub fn round1<R: RngCore>(
    rng: &mut R,
    k: &IcyKeys,
    variant: Variant,
    i: usize,
    req: &Request,
    tok: &Token,
    musig: Option<&MusigCtx>,
) -> Option<Round1> {
    let pos = req.set.iter().position(|&j| j == i)?;
    if !check_request(k, variant, req) {
        return None;
    }
    let g = g1_generator();
    let h = h1(&req.x);
    let sk = k.sks[i - 1];
    let gamma = h * sk;
    let cp_tag = variant.tag("CP");
    let pi = cp::prove(rng, &cp_tag, &g, &h, &k.vks[i - 1], &gamma, &sk);
    let dbar = h * tok.d;
    let ebar = h * tok.e;
    let pibar = (variant != Variant::Icy).then(|| {
        (
            cp::prove(rng, &cp_tag, &g, &h, &tok.public.d, &dbar, &tok.d),
            cp::prove(rng, &cp_tag, &g, &h, &tok.public.e, &ebar, &tok.e),
        )
    });
    let zhat = (variant == Variant::IcyA).then(|| {
        let ctx = musig.expect("Icy-A needs the MuSig2 context");
        tok.r1 + ctx.b * tok.r2 + ctx.chat * ctx.mu[pos] * k.a[i - 1]
    });
    Some(Round1 { i, gamma, pi, dbar, ebar, pibar, zhat })
}

/// Values that every party and the combiner derive from the round-1 messages.
#[derive(Clone, Debug)]
pub struct Session {
    pub h: G1,
    pub rho: Vec<Scalar>,
    pub lambda: Vec<Scalar>,
    pub gamma: G1,
    pub r: G1,
    pub rbar: G1,
    pub c: Scalar,
}

pub fn binding_values(variant: Variant, req: &Request) -> Vec<Scalar> {
    let bm = bitmap(&req.set);
    let tag = variant.tag("BIND");
    match variant {
        Variant::Icy => req
            .set
            .iter()
            .map(|&l| hash_to_scalar(&tag, &[&(l as u64).to_be_bytes(), &req.x, &bm]))
            .collect(),
        _ => {
            let mut ts = Vec::with_capacity(req.tokens.len() * 2 * G1_LEN);
            for t in &req.tokens {
                ts.extend_from_slice(&g1_bytes(&t.d));
                ts.extend_from_slice(&g1_bytes(&t.e));
            }
            let td = keccak(&[&ts]);
            req.set
                .iter()
                .map(|&l| hash_to_scalar(&tag, &[&(l as u64).to_be_bytes(), &req.x, &bm, &td]))
                .collect()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn challenge(variant: Variant, pk: &G1, h: &G1, gamma: &G1, r: &G1, rbar: &G1, x: &Input, set: &[u8; 32]) -> Scalar {
    let g = g1_bytes(&g1_generator());
    let (pk, h, gamma, r, rbar) = (g1_bytes(pk), g1_bytes(h), g1_bytes(gamma), g1_bytes(r), g1_bytes(rbar));
    let tag = variant.tag("CHAL");
    match variant {
        Variant::Icy => hash_to_scalar(&tag, &[&g, &h, &pk, &gamma, &r, &rbar, x]),
        _ => hash_to_scalar(&tag, &[&g, &h, &pk, &gamma, &r, &rbar, x, set]),
    }
}

/// Checks the round-1 proofs of the quorum (Icy-N, Icy-A: done by every
/// party before responding; all variants: done by the combiner).
pub fn check_round1(k: &IcyKeys, variant: Variant, req: &Request, msgs: &[Round1]) -> bool {
    let g = g1_generator();
    let h = h1(&req.x);
    let cp_tag = variant.tag("CP");
    msgs.len() == req.set.len()
        && msgs.iter().zip(&req.set).zip(&req.tokens).all(|((m, &l), t)| {
            m.i == l
                && cp::verify(&cp_tag, &g, &h, &k.vks[l - 1], &m.gamma, &m.pi)
                && match (variant, m.pibar) {
                    (Variant::Icy, _) => true,
                    (_, Some((pd, pe))) => {
                        cp::verify(&cp_tag, &g, &h, &t.d, &m.dbar, &pd)
                            && cp::verify(&cp_tag, &g, &h, &t.e, &m.ebar, &pe)
                    }
                    _ => false,
                }
        })
}

pub fn session(k: &IcyKeys, variant: Variant, req: &Request, msgs: &[Round1]) -> Session {
    let h = h1(&req.x);
    let rho = binding_values(variant, req);
    let lambda = lagrange_at_zero(&req.set);
    let gammas: Vec<G1> = msgs.iter().map(|m| m.gamma).collect();
    let gamma = g1_msm(&gammas, &lambda);
    let mut pts = Vec::with_capacity(2 * msgs.len());
    let mut bars = Vec::with_capacity(2 * msgs.len());
    let mut sc = Vec::with_capacity(2 * msgs.len());
    for ((m, t), r) in msgs.iter().zip(&req.tokens).zip(&rho) {
        pts.push(t.d);
        pts.push(t.e);
        bars.push(m.dbar);
        bars.push(m.ebar);
        sc.push(Scalar::from(1u64));
        sc.push(*r);
    }
    let r = g1_msm(&pts, &sc);
    let rbar = g1_msm(&bars, &sc);
    let c = challenge(variant, &k.pk, &h, &gamma, &r, &rbar, &req.x, &bitmap(&req.set));
    Session { h, rho, lambda, gamma, r, rbar, c }
}

/// Round 2 of party `i`: checks the round-1 messages (Icy-N, Icy-A) and
/// returns `z_i`.
pub fn round2(k: &IcyKeys, variant: Variant, i: usize, req: &Request, msgs: &[Round1], tok: &Token) -> Option<Scalar> {
    let pos = req.set.iter().position(|&j| j == i)?;
    if variant != Variant::Icy && !check_round1(k, variant, req, msgs) {
        return None;
    }
    let s = session(k, variant, req, msgs);
    Some(tok.d + s.rho[pos] * tok.e + s.lambda[pos] * k.sks[i - 1] * s.c)
}

#[derive(Clone, Debug)]
pub struct IcyProof {
    pub gamma: G1,
    pub c: Scalar,
    pub z: Scalar,
    /// Quorum bitmap (Icy-N, Icy-A).
    pub set: [u8; 32],
    /// MuSig2 signature (Icy-A).
    pub rhat: G1,
    pub zhat: Scalar,
}

pub fn output(gamma: &G1) -> [u8; 32] {
    hash_to_bytes(H3, &[&g1_bytes(gamma)])
}

/// Combination: checks every contribution and aggregates. Returns `None` if a
/// contribution fails, in which case the combiner restarts with a new quorum.
pub fn combine(
    k: &IcyKeys,
    variant: Variant,
    req: &Request,
    msgs: &[Round1],
    zs: &[Scalar],
    musig: Option<&MusigCtx>,
) -> Option<([u8; 32], IcyProof)> {
    if !check_round1(k, variant, req, msgs) || zs.len() != msgs.len() {
        return None;
    }
    let s = session(k, variant, req, msgs);
    let g = g1_generator();
    for (pos, ((m, t), z)) in msgs.iter().zip(&req.tokens).zip(zs).enumerate() {
        let w = s.c * s.lambda[pos];
        let l = m.i;
        // g^{z_l} = D_l E_l^{rho_l} vk_l^{c lambda_l}
        let lhs = g1_msm(&[g, t.e, k.vks[l - 1]], &[*z, -s.rho[pos], -w]);
        // h^{z_l} = Dbar_l Ebar_l^{rho_l} gamma_l^{c lambda_l}
        let rhs = g1_msm(&[s.h, m.ebar, m.gamma], &[*z, -s.rho[pos], -w]);
        if lhs != t.d || rhs != m.dbar {
            return None;
        }
    }
    let z: Scalar = zs.iter().sum();
    let mut proof = IcyProof {
        gamma: s.gamma,
        c: s.c,
        z,
        set: if variant == Variant::Icy { [0u8; 32] } else { bitmap(&req.set) },
        rhat: <G1 as group::Group>::identity(),
        zhat: Scalar::from(0u64),
    };
    if variant == Variant::IcyA {
        let ctx = musig?;
        for (pos, (m, t)) in msgs.iter().zip(&req.tokens).enumerate() {
            let zh = m.zhat?;
            let lhs = g1_msm(&[g, t.r1, t.r2, k.xk[m.i - 1]], &[zh, -Scalar::from(1u64), -ctx.b, -ctx.chat * ctx.mu[pos]]);
            if !bool::from(group::Group::is_identity(&lhs)) {
                return None;
            }
        }
        proof.rhat = ctx.rhat;
        proof.zhat = msgs.iter().map(|m| m.zhat.unwrap()).sum();
    }
    Some((output(&s.gamma), proof))
}

/// Verification. `xk` holds the MuSig2 keys of all parties (Icy-A only).
#[allow(clippy::too_many_arguments)]
pub fn verify(
    variant: Variant,
    pk: &G1,
    pp_hash: &[u8; 32],
    xk: &[G1],
    t: usize,
    x: &Input,
    y: &[u8; 32],
    pi: &IcyProof,
) -> bool {
    let g = g1_generator();
    let h = h1(x);
    let set = bitmap_to_set(&pi.set);
    let size_ok = match variant {
        Variant::Icy => true,
        Variant::IcyN => set.len() == t + 1,
        Variant::IcyA => set.len() >= t + 1 && set.iter().all(|&i| i <= xk.len()),
    };
    if !size_ok || output(&pi.gamma) != *y {
        return false;
    }
    let r = g1_msm(&[g, *pk], &[pi.z, -pi.c]);
    let rbar = g1_msm(&[h, pi.gamma], &[pi.z, -pi.c]);
    if challenge(variant, pk, &h, &pi.gamma, &r, &rbar, x, &pi.set) != pi.c {
        return false;
    }
    if variant == Variant::IcyA {
        let keys: Vec<G1> = set.iter().map(|&i| xk[i - 1]).collect();
        let (_, x_agg) = musig_aggregate(&keys);
        let chat = musig_challenge(&x_agg, &pi.rhat, &m_x(pp_hash, x));
        return g1_msm(&[g, x_agg], &[pi.zhat, -chat]) == pi.rhat;
    }
    true
}

pub fn trace(k: &IcyKeys, variant: Variant, x: &Input, y: &[u8; 32], pi: &IcyProof) -> Option<Vec<usize>> {
    if variant == Variant::Icy {
        return None;
    }
    verify(variant, &k.pk, &k.pp_hash, &k.xk, k.params.t, x, y, pi).then(|| bitmap_to_set(&pi.set))
}

/// Runs one full evaluation with the quorum `set`; used by tests, the
/// benchmarks and the vector generator.
pub fn evaluate<R: RngCore>(
    rng: &mut R,
    k: &IcyKeys,
    variant: Variant,
    x: &Input,
    set: &[usize],
) -> Option<([u8; 32], IcyProof)> {
    let toks: Vec<Token> = set.iter().map(|_| preprocess(rng, variant)).collect();
    let req = Request { x: *x, set: set.to_vec(), tokens: toks.iter().map(|t| t.public).collect() };
    let ctx = (variant == Variant::IcyA).then(|| musig_ctx(k, &req));
    let msgs: Option<Vec<Round1>> = set
        .iter()
        .zip(&toks)
        .map(|(&i, t)| round1(rng, k, variant, i, &req, t, ctx.as_ref()))
        .collect();
    let msgs = msgs?;
    let zs: Option<Vec<Scalar>> = set.iter().zip(&toks).map(|(&i, t)| round2(k, variant, i, &req, &msgs, t)).collect();
    combine(k, variant, &req, &msgs, &zs?, ctx.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn run(variant: Variant, n: usize, set: &[usize]) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(21);
        let p = Params::honest_majority(n);
        let k = setup(&mut rng, p, variant);
        let x = [9u8; 32];
        let (y, pi) = evaluate(&mut rng, &k, variant, &x, set).unwrap();
        assert!(verify(variant, &k.pk, &k.pp_hash, &k.xk, p.t, &x, &y, &pi));
        // Uniqueness of the output across quorums.
        let other: Vec<usize> = (n - set.len() + 1..=n).collect();
        let (y2, _) = evaluate(&mut rng, &k, variant, &x, &other).unwrap();
        assert_eq!(y, y2);
        if variant != Variant::Icy {
            assert_eq!(trace(&k, variant, &x, &y, &pi), Some(set.to_vec()));
            let mut bad = pi.clone();
            let mut s2 = set.to_vec();
            s2[0] = if s2[0] == 1 { n } else { 1 };
            s2.sort();
            bad.set = bitmap(&s2);
            assert!(trace(&k, variant, &x, &y, &bad).is_none());
        }
    }

    #[test]
    fn icy() {
        run(Variant::Icy, 7, &[2, 3, 5, 6]);
    }

    #[test]
    fn icy_n() {
        run(Variant::IcyN, 7, &[2, 3, 5, 6]);
    }

    #[test]
    fn icy_a() {
        run(Variant::IcyA, 10, &[1, 4, 6, 8, 9, 10]);
    }

    #[test]
    fn icy_n_rejects_large_quorum() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(22);
        let k = setup(&mut rng, Params::honest_majority(7), Variant::IcyN);
        assert!(evaluate(&mut rng, &k, Variant::IcyN, &[0u8; 32], &[1, 2, 3, 4, 5]).is_none());
    }
}
