// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SymTest } from "a16z-halmos-cheatcodes/SymTest.sol";
import { Test } from "forge-std/Test.sol";
import { Counter } from "src/Counter.sol";

contract ProveCounterTest is Test, SymTest {

    Counter public counter;

    function setUp() public {
        counter = new Counter();
    }

    function check_Increment() public {
        uint256 startValue = svm.createUint256("starting value");
        vm.assume(startValue < type(uint256).max);
        counter.setNumber(startValue);
        (bool success,) = address(counter).call(abi.encodeCall(counter.increment, ()));
        assertTrue(success);
        assertEq(counter.number(), startValue + 1);
    }

}
