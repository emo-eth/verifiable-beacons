// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { DeterministicProxyFactory } from
    "deterministic-proxy-factory/DeterministicProxyFactory.sol";

import { PROXY_FACTORY_ADDRESS } from "deterministic-proxy-factory/Constants.sol";
import { DeterministicProxyFactoryFixture } from
    "deterministic-proxy-factory/fixtures/DeterministicProxyFactoryFixture.sol";
import { Test } from "forge-std/Test.sol";
import { TrustedImplementationRegistry } from "src/TrustedImplementationRegistry.sol";
import { UpgradeableBeacon } from "src/UpgradeableBeacon.sol";

contract MockImplementation { }

contract TrustedImplementationRegistryTest is Test {

    DeterministicProxyFactory deterministicProxyFactory;
    TrustedImplementationRegistry registry;
    UpgradeableBeacon trustedBeacon;
    MockImplementation mockImplementation;
    address beaconProxy;

    function setUp() public {
        mockImplementation = new MockImplementation();
        DeterministicProxyFactoryFixture.setUpDeterministicProxyFactory();
        registry = new TrustedImplementationRegistry(PROXY_FACTORY_ADDRESS);
        trustedBeacon = UpgradeableBeacon(
            registry.deployUpgradeableBeacon(uint96(0), address(this), address(mockImplementation))
        );

        deterministicProxyFactory = DeterministicProxyFactory(PROXY_FACTORY_ADDRESS);
        beaconProxy = deterministicProxyFactory.deployBeaconProxy({
            salt: bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            beacon: address(trustedBeacon),
            callData: "",
            immutableArgs: ""
        });
    }

    function test_registerBeaconProxy() public {
        registry.registerBeaconProxy({
            beaconProxy: beaconProxy,
            deployer: address(this),
            salt: uint96(0),
            beacon: address(trustedBeacon)
        });
    }

    function test_registerTrustedBeaconImplementation() public {
        registry.registerBeaconProxy({
            beaconProxy: beaconProxy,
            deployer: address(this),
            salt: uint96(0),
            beacon: address(trustedBeacon)
        });
        registry.registerTrustedBeaconImplementation({
            integrator: address(this),
            proxy: beaconProxy,
            implementation: address(mockImplementation),
            counter: 2
        });
        assertTrue(registry.checkProxy(beaconProxy));
    }

    function test_predictUpgradeableBeaconAddress() public {
        address predicted = registry.predictUpgradeableBeaconAddress(address(this), uint96(1));
        address actual =
            registry.deployUpgradeableBeacon(uint96(1), address(this), address(mockImplementation));
        assertEq(predicted, actual);
    }

}
