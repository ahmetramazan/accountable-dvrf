//! Shared primitives: encodings, hash functions, Shamir sharing and Lagrange
//! coefficients over the scalar field of BLS12-381.
//!
//! Encodings follow EIP-2537 without the 16-byte zero padding of each base
//! field element, so that the on-chain verifiers hash exactly the same bytes:
//! a G1 point is `x || y` (96 bytes) and a G2 point is
//! `x.c0 || x.c1 || y.c0 || y.c1` (192 bytes), all big-endian. The identity is
//! encoded as all zeros.

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand_core::RngCore;
use sha3::{Digest, Keccak256};

pub type G1 = G1Projective;
pub type G2 = G2Projective;

/// Length of a VRF input. On chain, inputs are 32-byte seeds.
pub type Input = [u8; 32];

pub const G1_LEN: usize = 96;
pub const G2_LEN: usize = 192;

/// Common prefix of all domain-separation tags of this implementation.
pub const DST_PREFIX: &str = "ADVRF-BLS12381-V01-";

/// RFC 9380 suite suffix for hashing to G1.
pub const H2C_SUITE: &str = "_BLS12381G1_XMD:SHA-256_SSWU_RO_";

pub fn g1_bytes(p: &G1) -> [u8; G1_LEN] {
    let mut out = [0u8; G1_LEN];
    if bool::from(p.is_identity()) {
        return out;
    }
    out.copy_from_slice(&p.to_affine().to_uncompressed());
    out
}

pub fn g2_bytes(p: &G2) -> [u8; G2_LEN] {
    let mut out = [0u8; G2_LEN];
    if bool::from(p.is_identity()) {
        return out;
    }
    // The zcash serialization writes c1 before c0; EIP-2537 writes c0 first.
    let z = p.to_affine().to_uncompressed();
    out[0..48].copy_from_slice(&z[48..96]);
    out[48..96].copy_from_slice(&z[0..48]);
    out[96..144].copy_from_slice(&z[144..192]);
    out[144..192].copy_from_slice(&z[96..144]);
    out
}

pub fn g1_from_bytes(b: &[u8]) -> Option<G1> {
    let arr: [u8; G1_LEN] = b.try_into().ok()?;
    if arr.iter().all(|&x| x == 0) {
        return Some(G1::identity());
    }
    Option::<G1Affine>::from(G1Affine::from_uncompressed(&arr)).map(G1::from)
}

pub fn g2_from_bytes(b: &[u8]) -> Option<G2> {
    let arr: [u8; G2_LEN] = b.try_into().ok()?;
    if arr.iter().all(|&x| x == 0) {
        return Some(G2::identity());
    }
    let mut z = [0u8; G2_LEN];
    z[0..48].copy_from_slice(&arr[48..96]);
    z[48..96].copy_from_slice(&arr[0..48]);
    z[96..144].copy_from_slice(&arr[144..192]);
    z[144..192].copy_from_slice(&arr[96..144]);
    Option::<G2Affine>::from(G2Affine::from_uncompressed(&z)).map(G2::from)
}

pub fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes_be()
}

/// Interprets 32 big-endian bytes as an integer and reduces it modulo r.
/// This matches `uint256(x) % R` on chain.
pub fn scalar_from_u256(b: &[u8; 32]) -> Scalar {
    let mut hi = [0u64; 4];
    let mut lo = [0u64; 4];
    for k in 0..2 {
        hi[1 - k] = u64::from_be_bytes(b[8 * k..8 * k + 8].try_into().unwrap());
        lo[1 - k] = u64::from_be_bytes(b[16 + 8 * k..16 + 8 * k + 8].try_into().unwrap());
    }
    let hi = Scalar::from_u64s_le(&hi).unwrap();
    let lo = Scalar::from_u64s_le(&lo).unwrap();
    let two128 = Scalar::from_u64s_le(&[0, 0, 1, 0]).unwrap();
    hi * two128 + lo
}

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Hash to the scalar field: `keccak256(tag || parts) mod r`.
pub fn hash_to_scalar(tag: &str, parts: &[&[u8]]) -> Scalar {
    let mut h = Keccak256::new();
    h.update(DST_PREFIX.as_bytes());
    h.update(tag.as_bytes());
    for p in parts {
        h.update(p);
    }
    scalar_from_u256(&h.finalize().into())
}

/// Hash to 32 bytes, used for VRF outputs: `keccak256(tag || parts)`.
pub fn hash_to_bytes(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(DST_PREFIX.as_bytes());
    h.update(tag.as_bytes());
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The full RFC 9380 domain-separation tag for the random oracle `name`.
pub fn h2c_dst(name: &str) -> Vec<u8> {
    format!("{DST_PREFIX}{name}{H2C_SUITE}").into_bytes()
}

/// Hash to G1 with the RFC 9380 suite BLS12381G1_XMD:SHA-256_SSWU_RO_.
pub fn hash_to_g1(name: &str, msg: &[u8]) -> G1 {
    G1::hash_to_curve(msg, &h2c_dst(name), &[])
}

pub fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::random(rng)
}

pub fn random_nonzero_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Shamir sharing of a random secret with a polynomial of degree `t`.
/// Returns `(sk, [sk_1, ..., sk_n])`, with party indices starting at 1.
pub fn shamir_deal<R: RngCore>(rng: &mut R, t: usize, n: usize) -> (Scalar, Vec<Scalar>) {
    let coeffs: Vec<Scalar> = (0..=t).map(|_| Scalar::random(&mut *rng)).collect();
    let shares = (1..=n as u64)
        .map(|i| {
            let x = Scalar::from(i);
            coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
        })
        .collect();
    (coeffs[0], shares)
}

/// Lagrange coefficients at 0 for the index set `set` (indices start at 1),
/// computed with a single field inversion.
pub fn lagrange_at_zero(set: &[usize]) -> Vec<Scalar> {
    let xs: Vec<Scalar> = set.iter().map(|&i| Scalar::from(i as u64)).collect();
    let mut nums = Vec::with_capacity(xs.len());
    let mut dens = Vec::with_capacity(xs.len());
    for (a, xa) in xs.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (b, xb) in xs.iter().enumerate() {
            if a != b {
                num *= xb;
                den *= xb - xa;
            }
        }
        nums.push(num);
        dens.push(den);
    }
    // Batch inversion.
    let mut prefix = Vec::with_capacity(dens.len());
    let mut acc = Scalar::ONE;
    for d in &dens {
        prefix.push(acc);
        acc *= d;
    }
    let mut inv = acc.invert().unwrap();
    let mut out = vec![Scalar::ZERO; dens.len()];
    for k in (0..dens.len()).rev() {
        out[k] = nums[k] * inv * prefix[k];
        inv *= dens[k];
    }
    out
}

/// Signer sets are encoded as a 256-bit bitmap, bit `i-1` for party `i`.
/// Committees are therefore limited to 256 parties.
pub fn bitmap(set: &[usize]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for &i in set {
        assert!((1..=256).contains(&i));
        let bit = i - 1;
        out[31 - bit / 8] |= 1 << (bit % 8);
    }
    out
}

pub fn bitmap_to_set(bm: &[u8; 32]) -> Vec<usize> {
    let mut set = Vec::new();
    for bit in 0..256 {
        if bm[31 - bit / 8] >> (bit % 8) & 1 == 1 {
            set.push(bit + 1);
        }
    }
    set
}

pub fn g1_msm(points: &[G1], scalars: &[Scalar]) -> G1 {
    G1::multi_exp(points, scalars)
}

pub fn g1_generator() -> G1 {
    G1::generator()
}

pub fn g2_generator() -> G2 {
    G2::generator()
}

/// Parameters of a benchmark run: committee size, threshold and quorum.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub n: usize,
    pub t: usize,
}

impl Params {
    /// The parameters of the paper: `t = floor((n-1)/2)`.
    pub fn honest_majority(n: usize) -> Self {
        Params { n, t: (n - 1) / 2 }
    }

    /// The smallest quorum, `{1, ..., t+1}`.
    pub fn min_quorum(&self) -> Vec<usize> {
        (1..=self.t + 1).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn lagrange_reconstructs() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let (sk, shares) = shamir_deal(&mut rng, 3, 7);
        let set = vec![2, 3, 5, 7];
        let lam = lagrange_at_zero(&set);
        let rec: Scalar = set.iter().zip(&lam).map(|(&i, l)| shares[i - 1] * l).sum();
        assert_eq!(rec, sk);
    }

    #[test]
    fn encodings_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let a = G1::generator() * random_scalar(&mut rng);
        let b = G2::generator() * random_scalar(&mut rng);
        assert_eq!(g1_from_bytes(&g1_bytes(&a)).unwrap(), a);
        assert_eq!(g2_from_bytes(&g2_bytes(&b)).unwrap(), b);
        assert_eq!(bitmap_to_set(&bitmap(&[1, 5, 9, 100])), vec![1, 5, 9, 100]);
    }

    #[test]
    fn scalar_reduction() {
        let x = [0xffu8; 32];
        let s = scalar_from_u256(&x);
        // 2^256 - 1 mod r, checked against 2*(2^255) - 1.
        let two = Scalar::from(2u64);
        let mut p = Scalar::ONE;
        for _ in 0..256 {
            p *= two;
        }
        assert_eq!(s, p - Scalar::ONE);
    }
}

/// Checks `prod_k e(a_k, b_k) = 1` with one multi-Miller loop and one final
/// exponentiation, as the EIP-2537 pairing precompile does.
pub fn pairing_check(terms: &[(G1, G2)]) -> bool {
    use pairing::{MillerLoopResult, MultiMillerLoop};
    let a: Vec<G1Affine> = terms.iter().map(|(p, _)| p.to_affine()).collect();
    let b: Vec<blstrs::G2Prepared> = terms.iter().map(|(_, q)| q.to_affine().into()).collect();
    let refs: Vec<(&G1Affine, &blstrs::G2Prepared)> = a.iter().zip(b.iter()).collect();
    let r = blstrs::Bls12::multi_miller_loop(&refs).final_exponentiation();
    bool::from(r.is_identity())
}
