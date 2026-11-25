// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {BLS12381 as B} from "../src/BLS12381.sol";

contract PopcountTest is Test {
    function naive(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            c += x & 1;
            x >>= 1;
        }
    }

    function test_edges() public pure {
        assertEq(B.popcount(0), 0);
        assertEq(B.popcount(type(uint256).max), 256);
        assertEq(B.popcount(1 << 255), 1);
    }

    function testFuzz_popcount(uint256 x) public pure {
        assertEq(B.popcount(x), naive(x));
    }
}
