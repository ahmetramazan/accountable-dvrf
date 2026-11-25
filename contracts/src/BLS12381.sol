// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title BLS12-381 helpers on top of the EIP-2537 precompiles.
/// @notice Points are handled in memory in the EIP-2537 encoding: a G1 point is
/// 128 bytes and a G2 point is 256 bytes, each base field element padded to 64
/// bytes. In calldata, in storage and in every hash input, points use the
/// "raw" encoding without the padding: 96 bytes for G1 and 192 bytes for G2,
/// in the order x.c0 || x.c1 || y.c0 || y.c1 for G2.
library BLS12381 {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    // Base field modulus p, split into its high 16 bytes and low 32 bytes.
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    address internal constant SHA256 = address(0x02);
    address internal constant MODEXP = address(0x05);
    address internal constant G1ADD = address(0x0b);
    address internal constant G1MSM = address(0x0c);
    address internal constant G2ADD = address(0x0d);
    address internal constant PAIRING = address(0x0f);
    address internal constant MAP_FP_TO_G1 = address(0x10);

    /// Raw encoding of the generator of G1.
    bytes internal constant G1_GEN_RAW =
        hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    /// Raw encoding of the negated generator of G2.
    bytes internal constant NEG_G2_RAW =
        hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb813e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e0d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa13fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    error PrecompileFailed(address precompile);

    // ---------------------------------------------------------------------
    // Encodings
    // ---------------------------------------------------------------------

    /// Pads `k` consecutive 48-byte field elements at memory pointer `src`
    /// into 64-byte words at `dst`.
    function _pad(uint256 src, uint256 dst, uint256 k) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let o := add(dst, mul(i, 64))
                mstore(o, 0)
                mcopy(add(o, 16), add(src, mul(i, 48)), 48)
            }
        }
    }

    /// Removes the padding of `k` field elements.
    function _unpad(uint256 src, uint256 dst, uint256 k) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                mcopy(add(dst, mul(i, 48)), add(add(src, mul(i, 64)), 16), 48)
            }
        }
    }

    function g1FromRaw(bytes memory raw) internal pure returns (bytes memory p) {
        require(raw.length == 96, "G1 length");
        p = new bytes(128);
        uint256 s;
        uint256 d;
        assembly ("memory-safe") {
            s := add(raw, 32)
            d := add(p, 32)
        }
        _pad(s, d, 2);
    }

    function g1FromCalldata(bytes calldata raw) internal pure returns (bytes memory p) {
        require(raw.length == 96, "G1 length");
        p = new bytes(128);
        assembly ("memory-safe") {
            let d := add(p, 32)
            calldatacopy(add(d, 16), raw.offset, 48)
            calldatacopy(add(d, 80), add(raw.offset, 48), 48)
        }
    }

    function g2FromRaw(bytes memory raw) internal pure returns (bytes memory p) {
        require(raw.length == 192, "G2 length");
        p = new bytes(256);
        uint256 s;
        uint256 d;
        assembly ("memory-safe") {
            s := add(raw, 32)
            d := add(p, 32)
        }
        _pad(s, d, 4);
    }

    function g2FromCalldata(bytes calldata raw) internal pure returns (bytes memory p) {
        require(raw.length == 192, "G2 length");
        p = new bytes(256);
        assembly ("memory-safe") {
            let d := add(p, 32)
            calldatacopy(add(d, 16), raw.offset, 48)
            calldatacopy(add(d, 80), add(raw.offset, 48), 48)
            calldatacopy(add(d, 144), add(raw.offset, 96), 48)
            calldatacopy(add(d, 208), add(raw.offset, 144), 48)
        }
    }

    /// Loads a G1 point kept in storage as three words of raw encoding.
    function g1FromWords(bytes32[3] storage w) internal view returns (bytes memory p) {
        p = new bytes(128);
        bytes32 a = w[0];
        bytes32 b = w[1];
        bytes32 c = w[2];
        assembly ("memory-safe") {
            let t := mload(0x40)
            mstore(t, a)
            mstore(add(t, 32), b)
            mstore(add(t, 64), c)
            let d := add(p, 32)
            mcopy(add(d, 16), t, 48)
            mcopy(add(d, 80), add(t, 48), 48)
        }
    }

    /// Loads a G2 point kept in storage as six words of raw encoding.
    function g2FromWords(bytes32[6] storage w) internal view returns (bytes memory p) {
        p = new bytes(256);
        bytes memory raw = abi.encodePacked(w[0], w[1], w[2], w[3], w[4], w[5]);
        uint256 s;
        uint256 d;
        assembly ("memory-safe") {
            s := add(raw, 32)
            d := add(p, 32)
        }
        _pad(s, d, 4);
    }

    /// The 32-byte word of `raw` at byte offset `off`.
    function wordAt(bytes memory raw, uint256 off) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(raw, 32), off))
        }
    }

    function toWords3(bytes memory raw) internal pure returns (bytes32[3] memory w) {
        require(raw.length == 96, "G1 length");
        assembly ("memory-safe") {
            mstore(w, mload(add(raw, 32)))
            mstore(add(w, 32), mload(add(raw, 64)))
            mstore(add(w, 64), mload(add(raw, 96)))
        }
    }

    function toWords6(bytes memory raw) internal pure returns (bytes32[6] memory w) {
        require(raw.length == 192, "G2 length");
        for (uint256 i = 0; i < 6; i++) {
            bytes32 v;
            assembly ("memory-safe") {
                v := mload(add(add(raw, 32), mul(i, 32)))
            }
            w[i] = v;
        }
    }

    /// Raw encoding of a G1 point given in the EIP-2537 encoding.
    function g1Raw(bytes memory p) internal pure returns (bytes memory raw) {
        raw = new bytes(96);
        uint256 s;
        uint256 d;
        assembly ("memory-safe") {
            s := add(p, 32)
            d := add(raw, 32)
        }
        _unpad(s, d, 2);
    }

    // ---------------------------------------------------------------------
    // Precompiles
    // ---------------------------------------------------------------------

    function _call(address target, bytes memory input, uint256 outLen) private view returns (bytes memory out) {
        out = new bytes(outLen);
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), target, add(input, 32), mload(input), add(out, 32), outLen)
        }
        if (!ok) revert PrecompileFailed(target);
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return _call(G1ADD, bytes.concat(a, b), 128);
    }

    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        return _call(G2ADD, bytes.concat(a, b), 256);
    }

    /// Scalar multiplication, i.e., a multi-scalar multiplication of size one.
    function g1Mul(bytes memory p, uint256 s) internal view returns (bytes memory) {
        return _call(G1MSM, bytes.concat(p, bytes32(s)), 128);
    }

    /// Multi-scalar multiplication; `pairs` is the concatenation of
    /// (128-byte point, 32-byte scalar) pairs.
    function g1Msm(bytes memory pairs) internal view returns (bytes memory) {
        return _call(G1MSM, pairs, 128);
    }

    /// `prod e(P_i, Q_i) == 1` for the concatenation of (G1, G2) pairs.
    function pairing(bytes memory pairs) internal view returns (bool) {
        bytes memory out = _call(PAIRING, pairs, 32);
        return uint256(bytes32(out)) == 1;
    }

    function negG2() internal pure returns (bytes memory) {
        return g2FromRaw(NEG_G2_RAW);
    }

    function g1Gen() internal pure returns (bytes memory) {
        return g1FromRaw(G1_GEN_RAW);
    }

    // ---------------------------------------------------------------------
    // Hash to G1 (RFC 9380, BLS12381G1_XMD:SHA-256_SSWU_RO_)
    // ---------------------------------------------------------------------

    /// Reduces the 64-byte big-endian integer `hi || lo` modulo p and returns
    /// it as a padded 64-byte field element.
    function _modP(bytes32 hi, bytes32 lo) private view returns (bytes memory out) {
        out = new bytes(64);
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 64) // base length
            mstore(add(m, 32), 1) // exponent length
            mstore(add(m, 64), 48) // modulus length
            mstore(add(m, 96), hi)
            mstore(add(m, 128), lo)
            mstore8(add(m, 160), 1) // exponent
            mstore(add(m, 161), shl(128, P_HI))
            mstore(add(m, 177), P_LO)
            ok := staticcall(gas(), 0x05, m, 209, add(out, 48), 48)
        }
        if (!ok) revert PrecompileFailed(MODEXP);
    }

    function hashToG1(bytes memory dst, bytes memory message) internal view returns (bytes memory) {
        bytes memory dstPrime = bytes.concat(dst, bytes1(uint8(dst.length)));
        bytes32 b0 = sha256(bytes.concat(bytes32(0), bytes32(0), message, hex"008000", dstPrime));
        bytes32 b1 = sha256(bytes.concat(b0, hex"01", dstPrime));
        bytes32 b2 = sha256(bytes.concat(b0 ^ b1, hex"02", dstPrime));
        bytes32 b3 = sha256(bytes.concat(b0 ^ b2, hex"03", dstPrime));
        bytes32 b4 = sha256(bytes.concat(b0 ^ b3, hex"04", dstPrime));
        bytes memory q0 = _call(MAP_FP_TO_G1, _modP(b1, b2), 128);
        bytes memory q1 = _call(MAP_FP_TO_G1, _modP(b3, b4), 128);
        return g1Add(q0, q1);
    }

    // ---------------------------------------------------------------------
    // Scalars and signer sets
    // ---------------------------------------------------------------------

    function popcount(uint256 x) internal pure returns (uint256 c) {
        unchecked {
            while (x != 0) {
                x &= x - 1;
                c++;
            }
        }
    }

    /// Modular inverse in the scalar field by Fermat, with MODEXP.
    function invR(uint256 a) internal view returns (uint256 inv) {
        bool ok;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 32), 32)
            mstore(add(m, 64), 32)
            mstore(add(m, 96), a)
            mstore(add(m, 128), sub(R, 2))
            mstore(add(m, 160), R)
            ok := staticcall(gas(), 0x05, m, 192, m, 32)
            inv := mload(m)
        }
        if (!ok) revert PrecompileFailed(MODEXP);
    }

    /// Lagrange coefficients at 0 for the ordered index set `idx`, with one
    /// inversion.
    function lagrange(uint256[] memory idx) internal view returns (uint256[] memory lam) {
        uint256 k = idx.length;
        lam = new uint256[](k);
        uint256[] memory num = new uint256[](k);
        uint256[] memory den = new uint256[](k);
        uint256 prod = 1;
        for (uint256 a = 0; a < k; a++) {
            uint256 nu = 1;
            uint256 de = 1;
            for (uint256 b = 0; b < k; b++) {
                if (a != b) {
                    nu = mulmod(nu, idx[b], R);
                    de = mulmod(de, addmod(idx[b], R - idx[a], R), R);
                }
            }
            num[a] = nu;
            den[a] = prod; // prefix product before a
            prod = mulmod(prod, de, R);
            lam[a] = de; // keep de for the backward pass
        }
        uint256 inv = invR(prod);
        for (uint256 a = k; a > 0; a--) {
            uint256 i = a - 1;
            uint256 de = lam[i];
            lam[i] = mulmod(mulmod(num[i], inv, R), den[i], R);
            inv = mulmod(inv, de, R);
        }
    }
}
