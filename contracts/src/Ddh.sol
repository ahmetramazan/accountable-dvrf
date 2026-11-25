// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS12381 as B} from "./BLS12381.sol";

/// @title On-chain verifier for DDH-DVRF over G1 of BLS12-381.
/// @notice The proof is the list of the t+1 partial evaluations of the quorum,
/// in increasing order of index: for each, `v (96 bytes) || c (32) || z (32)`.
/// The verification keys are kept in storage (`verifyStored`) or passed in
/// calldata and checked against a stored digest (`verifyCalldata`).
contract DdhVerifier {
    bytes internal constant DST_H = "ADVRF-BLS12381-V01-DDH-H_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes internal constant TAG_CP = "ADVRF-BLS12381-V01-DDH-CP";
    bytes internal constant TAG_OUT = "ADVRF-BLS12381-V01-DDH-OUT";
    uint256 internal constant ENTRY = 160;

    uint256 public immutable n;
    uint256 public immutable t;
    bytes32 public immutable vksHash;
    bytes32[3][] internal vks;

    constructor(uint256 t_, bytes memory vksRaw) {
        require(vksRaw.length % 96 == 0 && vksRaw.length / 96 <= 256, "vks");
        t = t_;
        n = vksRaw.length / 96;
        vksHash = keccak256(vksRaw);
        for (uint256 i = 0; i < n; i++) {
            bytes32[3] storage w = vks.push();
            for (uint256 j = 0; j < 3; j++) w[j] = B.wordAt(vksRaw, i * 96 + j * 32);
        }
    }

    function _indices(uint256 set) internal view returns (bool ok, uint256[] memory idx) {
        if (set >> n != 0 || B.popcount(set) != t + 1) return (false, idx);
        idx = new uint256[](t + 1);
        uint256 k;
        for (uint256 i = 0; i < n; i++) {
            if ((set >> i) & 1 == 1) idx[k++] = i + 1;
        }
        ok = true;
    }

    /// Checks one Chaum–Pedersen proof that log_g vk = log_h v.
    function _cp(bytes memory g, bytes memory h, bytes memory vkRaw, bytes calldata e) internal view returns (bool) {
        bytes calldata vRaw = e[0:96];
        uint256 c = uint256(bytes32(e[96:128]));
        uint256 z = uint256(bytes32(e[128:160]));
        if (c >= B.R) return false;
        uint256 negC = B.R - c;
        bytes memory vk = B.g1FromRaw(vkRaw);
        bytes memory v = B.g1FromCalldata(vRaw);
        bytes memory a = B.g1Msm(bytes.concat(g, bytes32(z), vk, bytes32(negC)));
        bytes memory b = B.g1Msm(bytes.concat(h, bytes32(z), v, bytes32(negC)));
        uint256 c2 = uint256(
            keccak256(bytes.concat(TAG_CP, B.G1_GEN_RAW, B.g1Raw(h), vkRaw, vRaw, B.g1Raw(a), B.g1Raw(b)))
        ) % B.R;
        return c2 == c;
    }

    function _verify(bytes32 x, bytes32 y, uint256 set, bytes calldata proof, bytes memory vksRaw, bool fromCalldata)
        internal
        view
        returns (bool)
    {
        (bool ok, uint256[] memory idx) = _indices(set);
        if (!ok || proof.length != idx.length * ENTRY) return false;
        bytes memory g = B.g1Gen();
        bytes memory h = B.hashToG1(DST_H, abi.encodePacked(x));
        bytes memory msm = new bytes(idx.length * 160);
        uint256[] memory lam = B.lagrange(idx);
        for (uint256 k = 0; k < idx.length; k++) {
            bytes calldata e = proof[k * ENTRY:(k + 1) * ENTRY];
            bytes memory vkRaw;
            if (fromCalldata) {
                vkRaw = new bytes(96);
                uint256 off = (idx[k] - 1) * 96;
                for (uint256 w = 0; w < 3; w++) {
                    bytes32 word;
                    assembly ("memory-safe") {
                        word := mload(add(add(add(vksRaw, 32), off), mul(w, 32)))
                    }
                    assembly ("memory-safe") {
                        mstore(add(add(vkRaw, 32), mul(w, 32)), word)
                    }
                }
            } else {
                bytes32[3] storage s = vks[idx[k] - 1];
                vkRaw = abi.encodePacked(s[0], s[1], s[2]);
            }
            if (!_cp(g, h, vkRaw, e)) return false;
            bytes memory v = B.g1FromCalldata(e[0:96]);
            uint256 l = lam[k];
            assembly ("memory-safe") {
                let dst := add(add(msm, 32), mul(k, 160))
                mcopy(dst, add(v, 32), 128)
                mstore(add(dst, 128), l)
            }
        }
        bytes memory gamma = B.g1Msm(msm);
        return keccak256(bytes.concat(TAG_OUT, B.g1Raw(gamma))) == y;
    }

    function verifyStored(bytes32 x, bytes32 y, uint256 set, bytes calldata proof) external view returns (bool) {
        return _verify(x, y, set, proof, "", false);
    }

    function verifyCalldata(bytes32 x, bytes32 y, uint256 set, bytes calldata proof, bytes calldata vksRaw)
        external
        view
        returns (bool)
    {
        if (keccak256(vksRaw) != vksHash) return false;
        return _verify(x, y, set, proof, vksRaw, true);
    }
}
