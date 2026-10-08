// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";
import {G10bBase} from "test/guards/G10b_Base.sol";

contract G10bPrintFixtureTest is G10bBase {
    function test_print_fixture() public view {
        console2.log("safe", address(safe));
        console2.log("guard", address(guard));
        console2.log("A", address(A));
        console2.log("B", address(B));
        console2.log("C", address(C));
        console2.log("H", address(H));
        console2.log("D", D);
        console2.log("E", E);
        console2.log("M", M);
        console2.log("M2", M2);
        console2.log("U", address(multiSendCallOnly));
        console2.log("U2", address(U2));
        console2.log("MS", address(multiSend));
        console2.log("curator", curator);
        console2.logBytes32(_fixtureHash());
    }
}
