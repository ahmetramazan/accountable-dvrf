// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {GlowVerifier, GlowMspVerifier, GlowAsmVerifier} from "../src/Glow.sol";
import {DdhVerifier} from "../src/Ddh.sol";
import {IcyVerifier, IcyNVerifier, IcyAVerifier} from "../src/Icy.sol";

/// Deploys every verifier for every committee size and sends one verification
/// transaction per scheme and mode. The order of the transactions is written
/// to `results/labels.csv`, so that `gas_report` can match them with the
/// receipts of the broadcast.
contract Measure is Script {
    uint256[7] internal NS = [uint256(5), 6, 7, 10, 25, 50, 100];
    string internal labels = "scheme,mode,n,t,quorum,kind\n";
    string internal cur;

    function _load(string memory name, uint256 n) internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/../vectors/", name, "_n", vm.toString(n), ".json"));
    }

    function _label(string memory scheme, string memory mode, string memory kind) internal {
        labels = string.concat(labels, scheme, ",", mode, ",", cur, ",", kind, "\n");
    }

    function _send(address target, bytes memory data, string memory scheme, string memory mode) internal {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok && abi.decode(ret, (bool)), string.concat("verification failed: ", scheme, " ", mode));
        _label(scheme, mode, "verify");
    }

    function run() external {
        vm.startBroadcast();
        for (uint256 k = 0; k < NS.length; k++) {
            uint256 n = NS[k];
            string memory j = _load("glow", n);
            cur = string.concat(
                vm.toString(n), ",", vm.toString(vm.parseJsonUint(j, ".t")), ",", vm.toString(vm.parseJsonUint(j, ".quorum"))
            );
            _glow(n);
            _msp(n);
            _asm(n);
            _ddh(n);
            _icy(n);
        }
        vm.stopBroadcast();
        vm.writeFile(string.concat(vm.projectRoot(), "/../results/labels.csv"), labels);
    }

    function _glow(uint256 n) internal {
        string memory j = _load("glow", n);
        GlowVerifier v = new GlowVerifier(vm.parseJsonBytes(j, ".pk"));
        _label("GLOW-DVRF", "-", "deploy");
        _send(
            address(v),
            abi.encodeCall(
                v.verify, (vm.parseJsonBytes32(j, ".x"), vm.parseJsonBytes32(j, ".y"), vm.parseJsonBytes(j, ".sigma"))
            ),
            "GLOW-DVRF",
            "-"
        );
    }

    function _msp(uint256 n) internal {
        string memory j = _load("glow_msp", n);
        bytes memory keys = vm.parseJsonBytes(j, ".keys");
        GlowMspVerifier v = new GlowMspVerifier(
            vm.parseJsonBytes(j, ".pk"), vm.parseJsonBytes32(j, ".ppHash"), vm.parseJsonUint(j, ".t"), keys
        );
        _label("GLOW-A MSP-pop", "storage", "deploy");
        bytes32 x = vm.parseJsonBytes32(j, ".x");
        bytes32 y = vm.parseJsonBytes32(j, ".y");
        bytes memory sigma = vm.parseJsonBytes(j, ".sigma");
        uint256 set = vm.parseJsonUint(j, ".set");
        bytes memory s = vm.parseJsonBytes(j, ".s");
        _send(address(v), abi.encodeCall(v.verifyStored, (x, y, sigma, set, s)), "GLOW-A MSP-pop", "storage");
        _send(address(v), abi.encodeCall(v.verifyCalldata, (x, y, sigma, set, s, keys)), "GLOW-A MSP-pop", "calldata");
    }

    function _asm(uint256 n) internal {
        string memory j = _load("glow_asm", n);
        bytes memory h6 = vm.parseJsonBytes(j, ".h6");
        GlowAsmVerifier v = new GlowAsmVerifier(
            vm.parseJsonBytes(j, ".pk"),
            vm.parseJsonBytes32(j, ".ppHash"),
            vm.parseJsonBytes32(j, ".apkHash"),
            vm.parseJsonBytes(j, ".yAgg"),
            vm.parseJsonUint(j, ".t"),
            h6
        );
        _label("GLOW-A ASM-pop", "storage", "deploy");
        bytes32 x = vm.parseJsonBytes32(j, ".x");
        bytes32 y = vm.parseJsonBytes32(j, ".y");
        bytes memory sigma = vm.parseJsonBytes(j, ".sigma");
        uint256 set = vm.parseJsonUint(j, ".set");
        bytes memory pks = vm.parseJsonBytes(j, ".pks");
        bytes memory s = vm.parseJsonBytes(j, ".s");
        _send(address(v), abi.encodeCall(v.verifyStored, (x, y, sigma, set, pks, s)), "GLOW-A ASM-pop", "storage");
        _send(
            address(v), abi.encodeCall(v.verifyCalldata, (x, y, sigma, set, pks, s, h6)), "GLOW-A ASM-pop", "calldata"
        );
        _send(address(v), abi.encodeCall(v.verifyHashed, (x, y, sigma, set, pks, s)), "GLOW-A ASM-pop", "hashed");
    }

    function _ddh(uint256 n) internal {
        string memory j = _load("ddh", n);
        bytes memory vks = vm.parseJsonBytes(j, ".vks");
        DdhVerifier v = new DdhVerifier(vm.parseJsonUint(j, ".t"), vks);
        _label("DDH-DVRF", "storage", "deploy");
        bytes32 x = vm.parseJsonBytes32(j, ".x");
        bytes32 y = vm.parseJsonBytes32(j, ".y");
        uint256 set = vm.parseJsonUint(j, ".set");
        bytes memory proof = vm.parseJsonBytes(j, ".proof");
        _send(address(v), abi.encodeCall(v.verifyStored, (x, y, set, proof)), "DDH-DVRF", "storage");
        _send(address(v), abi.encodeCall(v.verifyCalldata, (x, y, set, proof, vks)), "DDH-DVRF", "calldata");
    }

    function _icy(uint256 n) internal {
        {
            string memory j = _load("icy", n);
            IcyVerifier v = new IcyVerifier(vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"));
            _label("Icy-DVRF", "-", "deploy");
            _send(
                address(v),
                abi.encodeCall(
                    v.verify,
                    (
                        vm.parseJsonBytes32(j, ".x"),
                        vm.parseJsonBytes32(j, ".y"),
                        vm.parseJsonBytes(j, ".gamma"),
                        vm.parseJsonUint(j, ".c"),
                        vm.parseJsonUint(j, ".z")
                    )
                ),
                "Icy-DVRF",
                "-"
            );
        }
        {
            string memory j = _load("icy_n", n);
            IcyNVerifier v = new IcyNVerifier(vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"));
            _label("Icy-N", "-", "deploy");
            _send(
                address(v),
                abi.encodeCall(
                    v.verify,
                    (
                        vm.parseJsonBytes32(j, ".x"),
                        vm.parseJsonBytes32(j, ".y"),
                        vm.parseJsonBytes(j, ".gamma"),
                        vm.parseJsonUint(j, ".c"),
                        vm.parseJsonUint(j, ".z"),
                        vm.parseJsonUint(j, ".set")
                    )
                ),
                "Icy-N",
                "-"
            );
        }
        _icyA(n);
    }

    function _icyA(uint256 n) internal {
        string memory j = _load("icy_a", n);
        bytes memory keys = vm.parseJsonBytes(j, ".keys");
        IcyAVerifier v = new IcyAVerifier(
            vm.parseJsonBytes(j, ".pk"), vm.parseJsonUint(j, ".t"), vm.parseJsonBytes32(j, ".ppHash"), keys
        );
        _label("Icy-A", "storage", "deploy");
        bytes32 x = vm.parseJsonBytes32(j, ".x");
        bytes32 y = vm.parseJsonBytes32(j, ".y");
        bytes memory gamma = vm.parseJsonBytes(j, ".gamma");
        uint256 c = vm.parseJsonUint(j, ".c");
        uint256 z = vm.parseJsonUint(j, ".z");
        uint256 set = vm.parseJsonUint(j, ".set");
        bytes memory rhat = vm.parseJsonBytes(j, ".rhat");
        uint256 zhat = vm.parseJsonUint(j, ".zhat");
        _send(address(v), abi.encodeCall(v.verifyStored, (x, y, gamma, c, z, set, rhat, zhat)), "Icy-A", "storage");
        _send(
            address(v), abi.encodeCall(v.verifyCalldata, (x, y, gamma, c, z, set, rhat, zhat, keys)), "Icy-A", "calldata"
        );
    }
}
