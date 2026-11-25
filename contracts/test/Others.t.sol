// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DdhVerifier} from "../src/Ddh.sol";
import {IcyVerifier, IcyNVerifier, IcyAVerifier} from "../src/Icy.sol";

contract OthersTest is Test {
    uint256[7] internal NS = [uint256(5), 6, 7, 10, 25, 50, 100];

    struct V {
        bytes32 x;
        bytes32 y;
        bytes gamma;
        uint256 c;
        uint256 z;
        uint256 set;
        bytes rhat;
        uint256 zhat;
        bytes keys;
    }

    function _load(string memory name, uint256 n) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/../vectors/", name, "_n", vm.toString(n), ".json"));
    }

    function _icy(string memory j) internal pure returns (V memory v) {
        v.x = vm.parseJsonBytes32(j, ".x");
        v.y = vm.parseJsonBytes32(j, ".y");
        v.gamma = vm.parseJsonBytes(j, ".gamma");
        v.c = vm.parseJsonUint(j, ".c");
        v.z = vm.parseJsonUint(j, ".z");
        v.set = vm.parseJsonUint(j, ".set");
        v.rhat = vm.parseJsonBytes(j, ".rhat");
        v.zhat = vm.parseJsonUint(j, ".zhat");
        v.keys = vm.parseJsonBytes(j, ".keys");
    }

    function test_ddh() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("ddh", NS[k]);
            bytes memory vks = vm.parseJsonBytes(j, ".vks");
            DdhVerifier v = new DdhVerifier(vm.parseJsonUint(j, ".t"), vks);
            bytes32 x = vm.parseJsonBytes32(j, ".x");
            bytes32 y = vm.parseJsonBytes32(j, ".y");
            uint256 set = vm.parseJsonUint(j, ".set");
            bytes memory proof = vm.parseJsonBytes(j, ".proof");
            assertTrue(v.verifyStored(x, y, set, proof));
            assertTrue(v.verifyCalldata(x, y, set, proof, vks));
            uint256 framed = (set & ~uint256(1)) | (uint256(1) << (NS[k] - 1));
            assertFalse(v.verifyStored(x, y, framed, proof));
        }
    }

    function test_icy() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("icy", NS[k]);
            IcyVerifier ver = new IcyVerifier(vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"));
            V memory v = _icy(j);
            assertTrue(ver.verify(v.x, v.y, v.gamma, v.c, v.z));
            assertFalse(ver.verify(v.x, v.y, v.gamma, v.c, v.z + 1));
        }
    }

    function test_icy_n() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("icy_n", NS[k]);
            IcyNVerifier ver = new IcyNVerifier(vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"));
            V memory v = _icy(j);
            assertTrue(ver.verify(v.x, v.y, v.gamma, v.c, v.z, v.set));
            uint256 framed = (v.set & ~uint256(1)) | (uint256(1) << (NS[k] - 1));
            assertFalse(ver.verify(v.x, v.y, v.gamma, v.c, v.z, framed));
        }
    }

    function test_icy_a() public {
        for (uint256 k = 0; k < NS.length; k++) {
            string memory j = _load("icy_a", NS[k]);
            V memory v = _icy(j);
            IcyAVerifier ver = new IcyAVerifier(
                vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"), vm.parseJsonBytes32(j, ".ppHash"), v.keys
            );
            assertTrue(ver.verifyStored(v.x, v.y, v.gamma, v.c, v.z, v.set, v.rhat, v.zhat));
            assertTrue(ver.verifyCalldata(v.x, v.y, v.gamma, v.c, v.z, v.set, v.rhat, v.zhat, v.keys));
            assertFalse(ver.verifyStored(v.x, v.y, v.gamma, v.c, v.z, v.set, v.rhat, v.zhat + 1));
        }
    }
}
