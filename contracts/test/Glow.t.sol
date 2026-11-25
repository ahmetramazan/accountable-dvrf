// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GlowVerifier, GlowMspVerifier, GlowAsmVerifier} from "../src/Glow.sol";

contract GlowTest is Test {
    uint256[7] internal NS = [uint256(5), 6, 7, 10, 25, 50, 100];

    function _load(string memory name, uint256 n) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/../vectors/", name, "_n", vm.toString(n), ".json"));
    }

    function test_glow() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("glow", NS[k]);
            GlowVerifier v = new GlowVerifier(vm.parseJsonBytes(j, ".pk"));
            bytes32 x = vm.parseJsonBytes32(j, ".x");
            bytes32 y = vm.parseJsonBytes32(j, ".y");
            bytes memory sigma = vm.parseJsonBytes(j, ".sigma");
            assertTrue(v.verify(x, y, sigma));
            assertFalse(v.verify(x ^ bytes32(uint256(1)), y, sigma));
            assertFalse(v.verify(x, y ^ bytes32(uint256(1)), sigma));
        }
    }

    function test_glow_msp() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("glow_msp", NS[k]);
            bytes memory keys = vm.parseJsonBytes(j, ".keys");
            GlowMspVerifier v = new GlowMspVerifier(
                vm.parseJsonBytes(j, ".pk"), vm.parseJsonBytes32(j, ".ppHash"), vm.parseJsonUint(j, ".t"), keys
            );
            bytes32 x = vm.parseJsonBytes32(j, ".x");
            bytes32 y = vm.parseJsonBytes32(j, ".y");
            bytes memory sigma = vm.parseJsonBytes(j, ".sigma");
            uint256 set = vm.parseJsonUint(j, ".set");
            bytes memory s = vm.parseJsonBytes(j, ".s");
            assertTrue(v.verifyStored(x, y, sigma, set, s));
            assertTrue(v.verifyCalldata(x, y, sigma, set, s, keys));
            // Framing attempt: replace a signer of the quorum by a non-signer.
            uint256 framed = (set & ~uint256(1)) | (uint256(1) << (NS[k] - 1));
            assertFalse(v.verifyStored(x, y, sigma, framed, s));
            assertFalse(v.verifyCalldata(x, y, sigma, framed, s, keys));
        }
    }

    function test_glow_asm() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("glow_asm", NS[k]);
            bytes memory h6 = vm.parseJsonBytes(j, ".h6");
            GlowAsmVerifier v = new GlowAsmVerifier(
                vm.parseJsonBytes(j, ".pk"),
                vm.parseJsonBytes32(j, ".ppHash"),
                vm.parseJsonBytes32(j, ".apkHash"),
                vm.parseJsonBytes(j, ".yAgg"),
                vm.parseJsonUint(j, ".t"),
                h6
            );
            bytes32 x = vm.parseJsonBytes32(j, ".x");
            bytes32 y = vm.parseJsonBytes32(j, ".y");
            bytes memory sigma = vm.parseJsonBytes(j, ".sigma");
            uint256 set = vm.parseJsonUint(j, ".set");
            bytes memory pks = vm.parseJsonBytes(j, ".pks");
            bytes memory s = vm.parseJsonBytes(j, ".s");
            assertTrue(v.verifyStored(x, y, sigma, set, pks, s));
            assertTrue(v.verifyCalldata(x, y, sigma, set, pks, s, h6));
            assertTrue(v.verifyHashed(x, y, sigma, set, pks, s));
            uint256 framed = (set & ~uint256(1)) | (uint256(1) << (NS[k] - 1));
            assertFalse(v.verifyStored(x, y, sigma, framed, pks, s));
        }
    }
}
