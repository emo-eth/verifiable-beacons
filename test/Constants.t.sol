// // SPDX-License-Identifier: Apache-2.0
// pragma solidity ^0.8.20;

// import { Test } from "forge-std/Test.sol";
// import {
//     VERIFIABLE_BEACON_RELAYER_EXTCODEHASH,
//     VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH
// } from "src/Constants.sol";
// import { VerifiableBeaconRelayer } from "src/VerifiableBeaconRelayer.sol";
// import { VerifiableUpgradeableBeacon } from "src/VerifiableUpgradeableBeacon.sol";

// contract ConstantsTest is Test {

//     function setUp() public { }

//     function test_constants() public {
//         assertEq(
//             VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH,
//             keccak256(type(VerifiableUpgradeableBeacon).runtimeCode)
//         );
//         assertEq(
//             VERIFIABLE_BEACON_RELAYER_EXTCODEHASH,
//             keccak256(type(VerifiableBeaconRelayer).runtimeCode)
//         );
//     }

// }
