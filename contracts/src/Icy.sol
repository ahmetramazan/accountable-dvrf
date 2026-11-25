// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS12381 as B} from "./BLS12381.sol";

/// @title On-chain verifiers for Icy-DVRF, Icy-N and Icy-A over G1 of
/// BLS12-381. The hash functions and encodings match `advrf/src/icy.rs`.
abstract contract IcyBase {
    bytes internal constant DST_H1 = "ADVRF-BLS12381-V01-ICY-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant TAG_H3 = "ADVRF-BLS12381-V01-ICY-H3";

    bytes32[3] internal pk;
    uint256 public immutable t;

    constructor(bytes memory pkRaw, uint256 t_) {
        pk = B.toWords3(pkRaw);
        t = t_;
    }

    /// Recomputes `R = g^z pk^-c` and `Rbar = h^z gamma^-c` and returns the
    /// raw encodings of `h`, `R` and `Rbar`.
    function _commitments(bytes32 x, bytes calldata gamma, uint256 c, uint256 z)
        internal
        view
        returns (bytes memory hRaw, bytes memory rRaw, bytes memory rbarRaw)
    {
        uint256 negC = B.R - c;
        bytes memory h = B.hashToG1(DST_H1, abi.encodePacked(x));
        rRaw = B.g1Raw(B.g1Msm(bytes.concat(B.g1Gen(), bytes32(z), B.g1FromWords(pk), bytes32(negC))));
        rbarRaw = B.g1Raw(B.g1Msm(bytes.concat(h, bytes32(z), B.g1FromCalldata(gamma), bytes32(negC))));
        hRaw = B.g1Raw(h);
    }

    function _pkRaw() internal view returns (bytes memory) {
        return abi.encodePacked(pk[0], pk[1], pk[2]);
    }

    function _output(bytes calldata gamma) internal pure returns (bytes32) {
        return keccak256(bytes.concat(TAG_H3, gamma));
    }
}

/// Icy-DVRF (not accountable).
contract IcyVerifier is IcyBase {
    bytes internal constant TAG_CHAL = "ADVRF-BLS12381-V01-ICY-CHAL";

    constructor(bytes memory pkRaw, uint256 t_) IcyBase(pkRaw, t_) {}

    function verify(bytes32 x, bytes32 y, bytes calldata gamma, uint256 c, uint256 z) external view returns (bool) {
        if (c >= B.R || _output(gamma) != y) return false;
        (bytes memory h, bytes memory r, bytes memory rbar) = _commitments(x, gamma, c, z);
        return uint256(keccak256(bytes.concat(TAG_CHAL, B.G1_GEN_RAW, h, _pkRaw(), gamma, r, rbar, x))) % B.R == c;
    }
}

/// Icy-N: the quorum S, with |S| = t+1, is part of the challenge.
contract IcyNVerifier is IcyBase {
    bytes internal constant TAG_CHAL = "ADVRF-BLS12381-V01-ICYN-CHAL";

    constructor(bytes memory pkRaw, uint256 t_) IcyBase(pkRaw, t_) {}

    function verify(bytes32 x, bytes32 y, bytes calldata gamma, uint256 c, uint256 z, uint256 set)
        external
        view
        returns (bool)
    {
        if (B.popcount(set) != t + 1 || c >= B.R || _output(gamma) != y) return false;
        (bytes memory h, bytes memory r, bytes memory rbar) = _commitments(x, gamma, c, z);
        return uint256(keccak256(bytes.concat(TAG_CHAL, B.G1_GEN_RAW, h, _pkRaw(), gamma, r, rbar, x, bytes32(set))))
            % B.R == c;
    }
}

/// Icy-A: the T-DLEQ proof of Icy-N with any |S| >= t+1, and a MuSig2
/// signature `(Rhat, zhat)` on `m_x = ppHash || x` under the aggregate key of
/// S. The MuSig2 keys are kept in storage (`verifyStored`) or passed in
/// calldata and checked against a stored digest (`verifyCalldata`).
contract IcyAVerifier is IcyBase {
    bytes internal constant TAG_CHAL = "ADVRF-BLS12381-V01-ICYN-CHAL";
    bytes internal constant TAG_AGG = "ADVRF-BLS12381-V01-MUSIG2-AGG";
    bytes internal constant TAG_SIG = "ADVRF-BLS12381-V01-MUSIG2-SIG";

    bytes32 public immutable ppHash;
    uint256 public immutable n;
    bytes32 public immutable keysHash;
    bytes32[3][] internal keys;

    constructor(bytes memory pkRaw, uint256 t_, bytes32 ppHash_, bytes memory keysRaw) IcyBase(pkRaw, t_) {
        require(keysRaw.length % 96 == 0 && keysRaw.length / 96 <= 256, "keys");
        ppHash = ppHash_;
        n = keysRaw.length / 96;
        keysHash = keccak256(keysRaw);
        for (uint256 i = 0; i < n; i++) {
            bytes32[3] storage w = keys.push();
            for (uint256 j = 0; j < 3; j++) w[j] = B.wordAt(keysRaw, i * 96 + j * 32);
        }
    }

    function _tdleq(bytes32 x, bytes32 y, bytes calldata gamma, uint256 c, uint256 z, uint256 set)
        internal
        view
        returns (bool)
    {
        if (set >> n != 0 || B.popcount(set) < t + 1 || c >= B.R || _output(gamma) != y) return false;
        (bytes memory h, bytes memory r, bytes memory rbar) = _commitments(x, gamma, c, z);
        return uint256(keccak256(bytes.concat(TAG_CHAL, B.G1_GEN_RAW, h, _pkRaw(), gamma, r, rbar, x, bytes32(set))))
            % B.R == c;
    }

    /// Checks `g^zhat = Rhat * Xagg^chat` for the raw keys of S in order.
    function _musig(bytes32 x, bytes memory keysS, uint256 k, bytes calldata rhat, uint256 zhat)
        internal
        view
        returns (bool)
    {
        if (zhat >= B.R) return false;
        bytes32 l = keccak256(keysS);
        bytes memory msm = new bytes(k * 160);
        for (uint256 i = 0; i < k; i++) {
            bytes memory key = new bytes(96);
            assembly ("memory-safe") {
                let src := add(add(keysS, 32), mul(i, 96))
                mcopy(add(key, 32), src, 96)
            }
            uint256 mu = uint256(keccak256(bytes.concat(TAG_AGG, l, key))) % B.R;
            bytes memory pt = B.g1FromRaw(key);
            assembly ("memory-safe") {
                let dst := add(add(msm, 32), mul(i, 160))
                mcopy(dst, add(pt, 32), 128)
                mstore(add(dst, 128), mu)
            }
        }
        bytes memory xagg = B.g1Msm(msm);
        bytes memory xaggRaw = B.g1Raw(xagg);
        uint256 chat = uint256(keccak256(bytes.concat(TAG_SIG, xaggRaw, rhat, ppHash, x))) % B.R;
        bytes memory lhs = B.g1Msm(bytes.concat(B.g1Gen(), bytes32(zhat), xagg, bytes32(B.R - chat)));
        return keccak256(B.g1Raw(lhs)) == keccak256(rhat);
    }

    function verifyStored(
        bytes32 x,
        bytes32 y,
        bytes calldata gamma,
        uint256 c,
        uint256 z,
        uint256 set,
        bytes calldata rhat,
        uint256 zhat
    ) external view returns (bool) {
        if (!_tdleq(x, y, gamma, c, z, set)) return false;
        uint256 k = B.popcount(set);
        bytes memory keysS = new bytes(k * 96);
        uint256 pos;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) {
                bytes32[3] storage w = keys[i];
                bytes32 a = w[0];
                bytes32 b = w[1];
                bytes32 d = w[2];
                assembly ("memory-safe") {
                    let dst := add(add(keysS, 32), mul(pos, 96))
                    mstore(dst, a)
                    mstore(add(dst, 32), b)
                    mstore(add(dst, 64), d)
                }
                pos++;
            }
        }
        return _musig(x, keysS, k, rhat, zhat);
    }

    function verifyCalldata(
        bytes32 x,
        bytes32 y,
        bytes calldata gamma,
        uint256 c,
        uint256 z,
        uint256 set,
        bytes calldata rhat,
        uint256 zhat,
        bytes calldata keysRaw
    ) external view returns (bool) {
        if (keccak256(keysRaw) != keysHash) return false;
        if (!_tdleq(x, y, gamma, c, z, set)) return false;
        uint256 k = B.popcount(set);
        bytes memory keysS = new bytes(k * 96);
        uint256 pos;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) {
                uint256 off = i * 96;
                assembly ("memory-safe") {
                    calldatacopy(add(add(keysS, 32), mul(pos, 96)), add(keysRaw.offset, off), 96)
                }
                pos++;
            }
        }
        return _musig(x, keysS, k, rhat, zhat);
    }
}
