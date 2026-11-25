// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS12381 as B} from "./BLS12381.sol";

/// @title On-chain verifiers for GLOW-DVRF and GLOW-A (MSP-pop and ASM-pop).
/// @notice The hash functions and encodings match the off-chain implementation
/// in `advrf/src/glow.rs`.
library GlowHash {
    bytes internal constant DST_H1 = "ADVRF-BLS12381-V01-GLOW-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant DST_H4 = "ADVRF-BLS12381-V01-GLOWA-H4_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant DST_H6 = "ADVRF-BLS12381-V01-GLOWA-H6_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant TAG_H2 = "ADVRF-BLS12381-V01-GLOW-H2";
    bytes internal constant TAG_RHO = "ADVRF-BLS12381-V01-GLOWA-RHO";

    function output(bytes calldata sigma) internal pure returns (bytes32) {
        return keccak256(bytes.concat(TAG_H2, sigma));
    }

    function h1(bytes32 x) internal view returns (bytes memory) {
        return B.hashToG1(DST_H1, abi.encodePacked(x));
    }
}

/// GLOW-DVRF: `e(sigma, -g2) * e(H1(x), pk) = 1` and `y = H2(sigma)`.
contract GlowVerifier {
    bytes32[6] internal pk;

    constructor(bytes memory pkRaw) {
        pk = B.toWords6(pkRaw);
    }

    function verify(bytes32 x, bytes32 y, bytes calldata sigma) external view returns (bool) {
        if (GlowHash.output(sigma) != y) return false;
        return B.pairing(bytes.concat(B.g1FromCalldata(sigma), B.negG2(), GlowHash.h1(x), B.g2FromWords(pk)));
    }
}

/// GLOW-A with MSP-pop. The keys AK_i are kept in storage (`verifyStored`)
/// or passed in calldata and checked against a stored digest
/// (`verifyCalldata`).
contract GlowMspVerifier {
    bytes32[6] internal pk;
    bytes32 public immutable ppHash;
    uint256 public immutable n;
    uint256 public immutable t;
    bytes32 public immutable keysHash;
    bytes32[6][] internal ak;

    constructor(bytes memory pkRaw, bytes32 ppHash_, uint256 t_, bytes memory keysRaw) {
        require(keysRaw.length % 192 == 0 && keysRaw.length / 192 <= 256, "keys");
        pk = B.toWords6(pkRaw);
        ppHash = ppHash_;
        t = t_;
        n = keysRaw.length / 192;
        keysHash = keccak256(keysRaw);
        for (uint256 i = 0; i < n; i++) {
            bytes32[6] storage w = ak.push();
            for (uint256 j = 0; j < 6; j++) w[j] = B.wordAt(keysRaw, i * 192 + j * 32);
        }
    }

    function _check(bytes32 x, bytes32 y, bytes calldata sigma, uint256 set, bytes calldata s)
        internal
        view
        returns (bool ok, uint256 rho)
    {
        if (set >> n != 0 || B.popcount(set) < t + 1) return (false, 0);
        if (GlowHash.output(sigma) != y) return (false, 0);
        rho = uint256(keccak256(bytes.concat(GlowHash.TAG_RHO, ppHash, x, y, sigma, bytes32(set), s))) % B.R;
        ok = true;
    }

    function _pairing(bytes32 x, bytes calldata sigma, bytes calldata s, uint256 rho, bytes memory pkS)
        internal
        view
        returns (bool)
    {
        bytes memory left = B.g1Add(B.g1FromCalldata(sigma), B.g1Mul(B.g1FromCalldata(s), rho));
        bytes memory hx = B.g1Mul(B.hashToG1(GlowHash.DST_H4, abi.encodePacked(ppHash, x)), rho);
        return B.pairing(bytes.concat(left, B.negG2(), GlowHash.h1(x), B.g2FromWords(pk), hx, pkS));
    }

    function verifyStored(bytes32 x, bytes32 y, bytes calldata sigma, uint256 set, bytes calldata s)
        external
        view
        returns (bool)
    {
        (bool ok, uint256 rho) = _check(x, y, sigma, set, s);
        if (!ok) return false;
        bytes memory pkS;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) {
                bytes memory k = B.g2FromWords(ak[i]);
                pkS = pkS.length == 0 ? k : B.g2Add(pkS, k);
            }
        }
        return _pairing(x, sigma, s, rho, pkS);
    }

    function verifyCalldata(
        bytes32 x,
        bytes32 y,
        bytes calldata sigma,
        uint256 set,
        bytes calldata s,
        bytes calldata keys
    ) external view returns (bool) {
        if (keccak256(keys) != keysHash) return false;
        (bool ok, uint256 rho) = _check(x, y, sigma, set, s);
        if (!ok) return false;
        bytes memory pkS;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) {
                bytes memory k = B.g2FromCalldata(keys[i * 192:(i + 1) * 192]);
                pkS = pkS.length == 0 ? k : B.g2Add(pkS, k);
            }
        }
        return _pairing(x, sigma, s, rho, pkS);
    }
}

/// GLOW-A with ASM-pop. The values H6(apk, i) are kept in storage
/// (`verifyStored`), passed in calldata and checked against a stored digest
/// (`verifyCalldata`), or hashed by the verifier (`verifyHashed`).
contract GlowAsmVerifier {
    bytes32[6] internal pk;
    bytes32[6] internal yAgg;
    bytes32 public immutable ppHash;
    bytes32 public immutable apkHash;
    uint256 public immutable n;
    uint256 public immutable t;
    bytes32 public immutable h6Hash;
    bytes32[3][] internal h6;

    constructor(
        bytes memory pkRaw,
        bytes32 ppHash_,
        bytes32 apkHash_,
        bytes memory yRaw,
        uint256 t_,
        bytes memory h6Raw
    ) {
        require(h6Raw.length % 96 == 0 && h6Raw.length / 96 <= 256, "h6");
        pk = B.toWords6(pkRaw);
        yAgg = B.toWords6(yRaw);
        ppHash = ppHash_;
        apkHash = apkHash_;
        t = t_;
        n = h6Raw.length / 96;
        h6Hash = keccak256(h6Raw);
        for (uint256 i = 0; i < n; i++) {
            bytes32[3] storage w = h6.push();
            for (uint256 j = 0; j < 3; j++) w[j] = B.wordAt(h6Raw, i * 96 + j * 32);
        }
    }

    function _check(bytes32 x, bytes32 y, bytes calldata sigma, uint256 set, bytes calldata pks, bytes calldata s)
        internal
        view
        returns (bool ok, uint256 rho)
    {
        if (set >> n != 0 || B.popcount(set) < t + 1) return (false, 0);
        if (GlowHash.output(sigma) != y) return (false, 0);
        rho = uint256(keccak256(bytes.concat(GlowHash.TAG_RHO, ppHash, x, y, sigma, bytes32(set), pks, s))) % B.R;
        ok = true;
    }

    function _pairing(
        bytes32 x,
        bytes calldata sigma,
        bytes calldata pks,
        bytes calldata s,
        uint256 rho,
        bytes memory hsum
    ) internal view returns (bool) {
        bytes memory left = B.g1Add(B.g1FromCalldata(sigma), B.g1Mul(B.g1FromCalldata(s), rho));
        bytes memory hx = B.g1Mul(B.hashToG1(GlowHash.DST_H4, abi.encodePacked(apkHash, ppHash, x)), rho);
        return B.pairing(
            bytes.concat(
                left,
                B.negG2(),
                GlowHash.h1(x),
                B.g2FromWords(pk),
                hx,
                B.g2FromCalldata(pks),
                B.g1Mul(hsum, rho),
                B.g2FromWords(yAgg)
            )
        );
    }

    function _acc(bytes memory acc, bytes memory p) private view returns (bytes memory) {
        return acc.length == 0 ? p : B.g1Add(acc, p);
    }

    function verifyStored(
        bytes32 x,
        bytes32 y,
        bytes calldata sigma,
        uint256 set,
        bytes calldata pks,
        bytes calldata s
    ) external view returns (bool) {
        (bool ok, uint256 rho) = _check(x, y, sigma, set, pks, s);
        if (!ok) return false;
        bytes memory hsum;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) hsum = _acc(hsum, B.g1FromWords(h6[i]));
        }
        return _pairing(x, sigma, pks, s, rho, hsum);
    }

    function verifyCalldata(
        bytes32 x,
        bytes32 y,
        bytes calldata sigma,
        uint256 set,
        bytes calldata pks,
        bytes calldata s,
        bytes calldata h6Values
    ) external view returns (bool) {
        if (keccak256(h6Values) != h6Hash) return false;
        (bool ok, uint256 rho) = _check(x, y, sigma, set, pks, s);
        if (!ok) return false;
        bytes memory hsum;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) hsum = _acc(hsum, B.g1FromCalldata(h6Values[i * 96:(i + 1) * 96]));
        }
        return _pairing(x, sigma, pks, s, rho, hsum);
    }

    function verifyHashed(
        bytes32 x,
        bytes32 y,
        bytes calldata sigma,
        uint256 set,
        bytes calldata pks,
        bytes calldata s
    ) external view returns (bool) {
        (bool ok, uint256 rho) = _check(x, y, sigma, set, pks, s);
        if (!ok) return false;
        bytes memory hsum;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) {
                hsum = _acc(hsum, B.hashToG1(GlowHash.DST_H6, abi.encodePacked(apkHash, i + 1)));
            }
        }
        return _pairing(x, sigma, pks, s, rho, hsum);
    }
}
