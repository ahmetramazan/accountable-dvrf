# Accountable DVRFs: implementation and benchmarks

Reference implementation of accountable distributed verifiable random
functions (ADVRFs) over BLS12-381, with off-chain timings and on-chain
verifiers whose gas is measured with real transactions.

| Scheme | Accountable | Off-chain (Rust) | On-chain verifier (Solidity) |
|---|---|---|---|
| GLOW-DVRF (baseline) | no | `glow` | `GlowVerifier` |
| **GLOW-A, MSP-pop** (main scheme) | yes, any corruptions | `glow::msp_*` | `GlowMspVerifier` |
| **GLOW-A, ASM-pop** (variant) | yes, any corruptions | `glow::asm_*` | `GlowAsmVerifier` |
| **GLOW-P** (private accountability, Groth–Sahai) | yes, to a tracer | `glowp` | off-chain only |
| DDH-DVRF (baseline) | yes, up to t corruptions | `ddh` | `DdhVerifier` |
| Icy-DVRF (baseline) | no | `icy` (`Variant::Icy`) | `IcyVerifier` |
| **Icy-A** (Icy-DVRF' + MuSig2, nu = 2) | yes, any corruptions | `icy` (`Variant::IcyA`) | `IcyAVerifier` |
| **Icy-N** (native, quorum in the challenge) | yes, up to t corruptions | `icy` (`Variant::IcyN`) | `IcyNVerifier` |

The benchmarks use the parameters of the paper: n = 5, 6, 7, 10, 25, 50, 100,
t = floor((n-1)/2) and the smallest quorum |S| = t+1.

## Layout

```
advrf/        Rust library (blstrs / blst) and tools
  src/common.rs   encodings, hash functions, Shamir sharing, Lagrange coefficients
  src/cp.rs       Chaum–Pedersen (DLEQ) proofs
  src/glow.rs     GLOW-DVRF, GLOW-A with MSP-pop and with ASM-pop
  src/glowp.rs    GLOW-P: Groth–Sahai commitments and proofs (SXDH), tracing, judge
  src/ddh.rs      DDH-DVRF
  src/icy.rs      Icy-DVRF, Icy-N, Icy-A
  src/bin/timings.rs         off-chain timings
  src/bin/vectors.rs         test vectors for the contracts
  src/bin/gas_report.rs      gas breakdown from transaction receipts
  src/bin/timings_report.rs  Markdown tables from the timings
contracts/    Foundry project
  src/BLS12381.sol  EIP-2537 wrappers and RFC 9380 hash to G1
  src/Glow.sol      GLOW-DVRF, GLOW-A (MSP-pop, ASM-pop) verifiers
  src/Ddh.sol       DDH-DVRF verifier
  src/Icy.sol       Icy-DVRF, Icy-N, Icy-A verifiers
  test/             checks every verifier against the Rust vectors
  script/Measure.s.sol  deploys all verifiers and sends verification transactions
scripts/      measure-gas.sh, timings.sh
vectors/      generated test vectors (JSON)
results/      generated tables (CSV and Markdown)
```

## Requirements

* Rust (stable, edition 2024)
* Foundry (forge, anvil) with support for the Osaka hard fork (EIP-2537 precompiles)

## Usage

```sh
# Unit tests of the schemes (correctness, uniqueness, tracing, framing attempts)
cd advrf && cargo test --release

# Off-chain timings -> results/timings.csv, results/timings.md
./scripts/timings.sh                  # all schemes, all n, 30 runs each
./scripts/timings.sh --n 5,10 --iters 100 --scheme glow-msp,icy-n

# Solidity tests against the Rust vectors
cd advrf && cargo run --release --bin vectors -- ../vectors
cd contracts && forge test

# Gas with real transactions on a local anvil node -> results/gas.csv, results/gas.md
./scripts/measure-gas.sh
```

## What is measured

**Off-chain.** Each value is the median over the runs, after one warm-up run,
on one core. Per-party steps are reported per party. `combine` is the full work
of the combiner once it has the messages of the quorum, including the checks
of all contributions. The distributed key generation is a one-time setup and
is replaced by a trusted dealer that outputs the same keys; the setup steps of
the multisignatures (key generation, checks of the proofs of possession, and
the group setup of ASM-pop) are timed separately. For the interactive Icy
schemes, `round1` is the partial evaluation (and, in Icy-A, the MuSig2
response), and `round2` is the T-DLEQ response, which in Icy-N and Icy-A
includes checking the Chaum–Pedersen proofs of the whole quorum.

**On-chain.** `scripts/measure-gas.sh` starts anvil with the Osaka rules, deploys
every verifier and sends one verification transaction per scheme, mode and n.
`gas_report` splits the `gasUsed` of each receipt into the intrinsic 21 000 gas,
the calldata gas (EIP-2028, 16 gas per non-zero and 4 per zero byte) and the
execution gas, and marks the transactions for which the calldata floor of
EIP-7623 applies. Per-signer data (MSP-pop keys, ASM-pop values H6(apk, i),
DDH-DVRF verification keys, MuSig2 keys) is either read from storage
(`storage`) or passed in calldata and checked against a stored digest
(`calldata`); ASM-pop can also hash the values itself (`hashed`). The summary
table reports the cheaper mode.

**GLOW-P.** The combiner commits to the quorum, the aggregate signature and
the aggregate key under a binding CRS and proves (E1)–(E4) with Groth–Sahai
proofs under SXDH; the proof has 11+6n elements of G1, 8+6n of G2 and one
scalar. Verification checks the GLOW part and all equations with one
multi-pairing: each 2x2 matrix of pairings is multiplied by `(alpha, 1)` and
`(beta, 1)^T`, each equation by a random weight, and the terms that share an
element of G2 are merged (Fiat–Shamir coefficients). `trace` extracts the
quorum and the aggregate signature with the trapdoor, and `judge` checks them
publicly. GLOW-P has no on-chain verifier, since its estimated cost exceeds
2.6 M gas already for n = 5.

## Encodings and hash functions

The Rust code and the contracts use the same encodings and hash functions, and
`forge test` checks every contract against vectors from the Rust code.

* Points are encoded uncompressed as in EIP-2537, without the zero padding of
  the base field elements: 96 bytes for G1 and 192 bytes for G2
  (`x.c0 || x.c1 || y.c0 || y.c1`). The contracts pad them in memory.
* Hashes to G1 follow RFC 9380 with the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`
  and the tag `ADVRF-BLS12381-V01-<name>_BLS12381G1_XMD:SHA-256_SSWU_RO_`.
  On chain, `expand_message_xmd` uses the SHA-256 precompile, the reduction
  modulo p uses MODEXP, and the map uses `MAP_FP_TO_G1`.
* Hashes to scalars are `keccak256("ADVRF-BLS12381-V01-" || tag || data) mod r`,
  and VRF outputs are `keccak256("ADVRF-BLS12381-V01-" || tag || point)`.
* Inputs x are 32-byte seeds. Signer sets are 256-bit bitmaps (bit i-1 for
  party i), so committees have at most 256 parties.
* The signed message of the multisignatures is `m_x = ppHash || x`, where
  `ppHash` is the digest of `(pk, vk_1, ..., vk_n)`.
* GLOW-A batches its two pairing equations with a Fiat–Shamir coefficient
  `rho`, i.e., three pairings for MSP-pop and four for ASM-pop.

## Results

The tables are generated in `results/`:

* `results/gas.md`, `results/gas.csv`: verification and deployment gas.
* `results/timings.md`, `results/timings.csv`: off-chain timings.

## License

MIT
