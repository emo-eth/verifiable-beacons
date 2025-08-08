// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.20;

import { DeterministicProxyFactory } from
    "deterministic-proxy-factory/DeterministicProxyFactory.sol";

import { DETERMINISTIC_PROXY_FACTORY_ADDRESS } from "deterministic-proxy-factory/Constants.sol";
import { DeterministicProxyFactoryFixture } from
    "deterministic-proxy-factory/fixtures/DeterministicProxyFactoryFixture.sol";
import { Test } from "forge-std/Test.sol";
import { VerifiableBeaconRegistry } from "src/VerifiableBeaconRegistry.sol";
import { VerifiableUpgradeableBeacon } from "src/VerifiableUpgradeableBeacon.sol";

contract MockImplementation { }

contract TrustedImplementationRegistryTest is Test {

    DeterministicProxyFactory deterministicProxyFactory;
    VerifiableBeaconRegistry registry;
    VerifiableUpgradeableBeacon trustedBeacon;
    MockImplementation mockImplementation;
    address beaconProxy;

    function setUp() public {
        mockImplementation = new MockImplementation();
        DeterministicProxyFactoryFixture.setUpDeterministicProxyFactory();
        registry = new VerifiableBeaconRegistry();
        trustedBeacon = VerifiableUpgradeableBeacon(
            registry.deployVerifiableUpgradeableBeacon(
                uint96(0), address(this), address(mockImplementation)
            )
        );

        deterministicProxyFactory = DeterministicProxyFactory(DETERMINISTIC_PROXY_FACTORY_ADDRESS);
        beaconProxy = deterministicProxyFactory.deployBeaconProxy({
            salt: bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            beacon: address(trustedBeacon),
            callData: "",
            immutableArgs: ""
        });
    }

    function test_registerVerifiedBeaconProxy() public {
        registry.registerVerifiedBeaconProxy(
            beaconProxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(trustedBeacon)
        );
        (bool isRelayer, address beaconOrRelayer) = registry.beacons(beaconProxy);
        assertEq(beaconOrRelayer, address(trustedBeacon));
        assertEq(isRelayer, false);
    }

}

import { VerifiableBeaconRelayer } from "src/VerifiableBeaconRelayer.sol";

contract FakeBeacon {

    address public impl;

    constructor(address _impl) {
        impl = _impl;
    }

    function implementation() external view returns (address) {
        return impl;
    }

}

contract FakeRelayer {

    address public beacon;

    constructor(address _beacon) {
        beacon = _beacon;
    }

    function implementation() external view returns (address) {
        return beacon;
    }

}

contract IntegratorWithOwner {

    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function owner() external view returns (address) {
        return _owner;
    }

}

contract VerifiableBeaconRegistryFullTest is Test {

    DeterministicProxyFactory deterministicProxyFactory;
    VerifiableBeaconRegistry registry;

    address internal deployer;
    address internal integrator;
    address internal other;

    function setUp() public {
        deployer = makeAddr("deployer");
        integrator = makeAddr("integrator");
        other = makeAddr("other");

        DeterministicProxyFactoryFixture.setUpDeterministicProxyFactory();
        deterministicProxyFactory = DeterministicProxyFactory(DETERMINISTIC_PROXY_FACTORY_ADDRESS);
        registry = new VerifiableBeaconRegistry();
    }

    function _deployVerifiableBeacon(address owner_, address impl_, uint96 salt)
        internal
        returns (VerifiableUpgradeableBeacon beacon)
    {
        vm.prank(deployer);
        beacon = VerifiableUpgradeableBeacon(
            registry.deployVerifiableUpgradeableBeacon(salt, owner_, impl_)
        );
    }

    function _deployVerifiableRelayer(address owner_, address beacon_, uint96 salt)
        internal
        returns (VerifiableBeaconRelayer relayer)
    {
        vm.prank(deployer);
        relayer = VerifiableBeaconRelayer(
            registry.deployVerifiableUpgradeableBeaconRelayer(salt, owner_, beacon_)
        );
    }

    function _deployDeterministicBeaconProxy(address beaconOrRelayer, uint96 salt)
        internal
        returns (address proxy)
    {
        bytes32 fullSalt = bytes32(uint256(uint160(address(this))) << 96 | salt);
        proxy = deterministicProxyFactory.deployBeaconProxy({
            salt: fullSalt,
            beacon: beaconOrRelayer,
            callData: "",
            immutableArgs: ""
        });
    }

    // Registration: Beacon Proxy
    function test_registerVerifiedBeaconProxy_success_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);

        vm.expectEmit(true, true, false, true);
        emit VerifiableBeaconRegistry.BeaconProxyVerified(proxy, address(beacon), false);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        (bool isRelayer, address beaconOrRelayer) = registry.beacons(proxy);
        assertEq(isRelayer, false);
        assertEq(beaconOrRelayer, address(beacon));
    }

    function test_registerVerifiedBeaconProxy_fail_AddressMismatch_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);

        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRegistry.BeaconProxyAddressMismatch.selector)
        );
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(1)),
            address(beacon)
        );
    }

    function test_registerVerifiedBeaconProxy_fail_ExtcodehashMismatch_full() public {
        MockImplementation impl = new MockImplementation();
        FakeBeacon fakeBeacon = new FakeBeacon(address(impl));
        address proxy = _deployDeterministicBeaconProxy(address(fakeBeacon), 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableBeaconRegistry.BeaconImplementationExtcodehashMismatch.selector
            )
        );
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(fakeBeacon)
        );
    }

    // Registration: Relayer Proxy
    function test_registerVerifiedBeaconRelayerProxy_success_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);

        vm.expectEmit(true, true, false, true);
        emit VerifiableBeaconRegistry.BeaconProxyVerified(proxy, address(relayer), true);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (bool isRelayer, address beaconOrRelayer) = registry.beacons(proxy);
        assertEq(isRelayer, true);
        assertEq(beaconOrRelayer, address(relayer));
    }

    function test_registerVerifiedBeaconRelayerProxy_fail_AddressMismatch_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);

        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRegistry.BeaconProxyAddressMismatch.selector)
        );
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(1)),
            address(relayer)
        );
    }

    function test_registerVerifiedBeaconRelayerProxy_fail_ExtcodehashMismatch_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        FakeRelayer fakeRelayer = new FakeRelayer(address(beacon));
        address proxy = _deployDeterministicBeaconProxy(address(fakeRelayer), 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableBeaconRegistry.BeaconRelayerExtcodehashMismatch.selector
            )
        );
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(fakeRelayer)
        );
    }

    // Trusted Implementations: Beacon
    function test_registerTrustedBeaconImplementation_success_byIntegrator_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon = _deployVerifiableBeacon(integrator, address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();

        vm.prank(integrator);
        vm.expectEmit(true, true, false, true);
        emit VerifiableBeaconRegistry.TrustedBeaconImplementationRegistered(
            integrator, proxy, currentImplementation, beaconCounter
        );
        registry.registerTrustedBeaconImplementation(
            integrator, proxy, currentImplementation, beaconCounter
        );

        vm.prank(integrator);
        bool ok = registry.verifyImplementation(proxy);
        assertTrue(ok);
    }

    function test_registerTrustedBeaconImplementation_success_byOwnerOfIntegrator_full() public {
        address admin = makeAddr("admin");
        IntegratorWithOwner integratorContract = new IntegratorWithOwner(admin);

        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(integratorContract), address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();

        vm.prank(admin);
        registry.registerTrustedBeaconImplementation(
            address(integratorContract), proxy, currentImplementation, beaconCounter
        );

        vm.prank(address(integratorContract));
        bool ok = registry.verifyImplementation(proxy);
        assertTrue(ok);
    }

    function test_registerTrustedBeaconImplementation_fail_NotCallerOrOwner_full() public {
        // Use an integrator that is a contract so owner() staticcall doesn't revert unexpectedly
        address admin = makeAddr("admin-not-owner");
        IntegratorWithOwner integratorContract = new IntegratorWithOwner(admin);

        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(integratorContract), address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();

        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRegistry.OnlyCallerOrOwner.selector));
        registry.registerTrustedBeaconImplementation(
            address(integratorContract), proxy, currentImplementation, beaconCounter
        );
    }

    function test_registerTrustedBeaconImplementation_fail_ProxyNotRegistered_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon = _deployVerifiableBeacon(integrator, address(impl), 0);
        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();

        vm.prank(integrator);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRegistry.BeaconProxyNotRegistered.selector)
        );
        registry.registerTrustedBeaconImplementation(
            integrator, address(0xdead), currentImplementation, beaconCounter
        );
    }

    function test_verifyImplementation_beacon_falseOnChange_full() public {
        MockImplementation impl1 = new MockImplementation();
        MockImplementation impl2 = new MockImplementation();
        VerifiableUpgradeableBeacon beacon = _deployVerifiableBeacon(integrator, address(impl1), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();
        vm.prank(integrator);
        registry.registerTrustedBeaconImplementation(
            integrator, proxy, currentImplementation, beaconCounter
        );
        vm.prank(integrator);
        assertTrue(registry.verifyImplementation(proxy));

        vm.prank(integrator);
        beacon.upgradeTo(address(impl2));
        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    // Trusted Implementations: Relayer
    function test_registerTrustedBeaconRelayerImplementation_success_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);

        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (address currentImplementation, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();

        vm.prank(integrator);
        vm.expectEmit(true, true, false, true);
        emit VerifiableBeaconRegistry.TrustedBeaconRelayerImplementationRegistered(
            integrator,
            proxy,
            address(relayer),
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter)
        );
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            currentBeacon,
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter)
        );

        vm.prank(integrator);
        assertTrue(registry.verifyImplementation(proxy));
    }

    function test_registerTrustedBeaconRelayerImplementation_fail_BeaconExtcodehashMismatch_onRegisterTrusted(
    ) public {
        // Set up a valid relayer proxy registration first
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);

        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        // Try to register trusted info with a beacon that has wrong extcodehash
        FakeBeacon fakeBeacon = new FakeBeacon(address(impl));
        (address currentImplementation, uint256 beaconCounter) = beacon.implementationAndCounter();
        (, uint256 relayerCounter) = relayer.beaconAndCounter();

        vm.prank(integrator);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifiableBeaconRegistry.BeaconImplementationExtcodehashMismatch.selector
            )
        );
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            address(fakeBeacon),
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter)
        );
    }

    function test_registerTrustedBeaconRelayerImplementation_fail_NotRelayer_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        address proxy = _deployDeterministicBeaconProxy(address(beacon), 0);
        registry.registerVerifiedBeaconProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(beacon)
        );

        vm.prank(integrator);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRegistry.NotBeaconRelayer.selector));
        registry.registerTrustedBeaconRelayerImplementation(
            integrator, proxy, address(beacon), 1, address(impl), 1
        );
    }

    function test_registerTrustedBeaconRelayerImplementation_fail_ProxyNotRegistered_full()
        public
    {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        vm.prank(integrator);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRegistry.BeaconProxyNotRegistered.selector)
        );
        registry.registerTrustedBeaconRelayerImplementation(
            integrator, address(0xdead), address(beacon), 1, address(impl), 1
        );
    }

    function test_verifyImplementation_relayer_falseOnChange_full() public {
        MockImplementation impl1 = new MockImplementation();
        MockImplementation impl2 = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl1), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (address currentImplementation, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();
        vm.prank(integrator);
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            currentBeacon,
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter)
        );
        vm.prank(integrator);
        assertTrue(registry.verifyImplementation(proxy));

        VerifiableUpgradeableBeacon(currentBeacon).upgradeTo(address(impl2));
        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    function test_verifyImplementation_relayer_falseOnRelayerCounterMismatch_only() public {
        // Set up relayer and register trusted info matching current state
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (address currentImplementation, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();

        // Register trusted info with WRONG relayerCounter but other fields equal
        vm.prank(integrator);
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            currentBeacon,
            uint96(relayerCounter + 1),
            currentImplementation,
            uint96(beaconCounter)
        );

        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    function test_verifyImplementation_relayer_falseOnBeaconMismatch_only() public {
        // Current relayer points to beaconA; we register trusted info pointing to beaconB but
        // keep implementation and counters matching current beaconA to isolate beacon mismatch
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beaconA =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableUpgradeableBeacon beaconB =
            _deployVerifiableBeacon(address(this), address(impl), 1);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beaconA), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (address currentImplementation, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();

        // Register trusted info with different beacon (same codehash), but same impl and counter
        // values from beaconA
        vm.prank(integrator);
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            address(beaconB),
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter)
        );

        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    function test_verifyImplementation_relayer_falseOnImplementationMismatch_only() public {
        MockImplementation impl1 = new MockImplementation();
        MockImplementation impl2 = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl1), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();

        // Register trusted info with wrong implementation address but correct counters
        vm.prank(integrator);
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            currentBeacon,
            uint96(relayerCounter),
            address(impl2),
            uint96(beaconCounter)
        );

        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    function test_verifyImplementation_relayer_falseOnBeaconCounterMismatch_only() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        address proxy = _deployDeterministicBeaconProxy(address(relayer), 0);
        registry.registerVerifiedBeaconRelayerProxy(
            proxy,
            DETERMINISTIC_PROXY_FACTORY_ADDRESS,
            bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
            address(relayer)
        );

        (address currentBeacon, uint256 relayerCounter) = relayer.beaconAndCounter();
        (address currentImplementation, uint256 beaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();

        // Register trusted info with wrong beaconCounter only
        vm.prank(integrator);
        registry.registerTrustedBeaconRelayerImplementation(
            integrator,
            proxy,
            currentBeacon,
            uint96(relayerCounter),
            currentImplementation,
            uint96(beaconCounter + 1)
        );

        vm.prank(integrator);
        assertFalse(registry.verifyImplementation(proxy));
    }

    function test_verifyImplementation_fail_ProxyNotRegistered_full() public {
        vm.prank(integrator);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRegistry.BeaconProxyNotRegistered.selector)
        );
        registry.verifyImplementation(address(0xBEEF));
    }

    // Deterministic Deployments & Predictions
    function test_predictVerifiableUpgradeableBeaconAddress_matchesDeployment_full() public {
        uint96 salt = 42;
        address predicted = registry.predictVerifiableUpgradeableBeaconAddress(deployer, salt);
        MockImplementation impl = new MockImplementation();
        vm.prank(deployer);
        address deployed =
            registry.deployVerifiableUpgradeableBeacon(salt, address(this), address(impl));
        assertEq(predicted, deployed);
    }

    function test_predictVerifiableBeaconRelayerAddress_matchesDeployment_full() public {
        uint96 salt = 77;
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 1);
        address predicted = registry.predictVerifiableBeaconRelayerAddress(deployer, salt);
        vm.prank(deployer);
        address deployed =
            registry.deployVerifiableUpgradeableBeaconRelayer(salt, address(this), address(beacon));
        assertEq(predicted, deployed);
    }

    function test_deriveBeaconProxyAddress_matchesFactory_Beacon_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        bytes32 fullSalt = bytes32(uint256(uint160(address(this))) << 96 | uint96(123));
        address predicted = registry.deriveBeaconProxyAddress(
            DETERMINISTIC_PROXY_FACTORY_ADDRESS, fullSalt, address(beacon)
        );
        address deployed = deterministicProxyFactory.deployBeaconProxy({
            salt: fullSalt,
            beacon: address(beacon),
            callData: "",
            immutableArgs: ""
        });
        assertEq(predicted, deployed);
    }

    function test_deriveBeaconProxyAddress_matchesFactory_Relayer_full() public {
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 0);
        VerifiableBeaconRelayer relayer =
            _deployVerifiableRelayer(address(this), address(beacon), 0);
        bytes32 fullSalt = bytes32(uint256(uint160(address(this))) << 96 | uint96(999));
        address predicted = registry.deriveBeaconProxyAddress(
            DETERMINISTIC_PROXY_FACTORY_ADDRESS, fullSalt, address(relayer)
        );
        address deployed = deterministicProxyFactory.deployBeaconProxy({
            salt: fullSalt,
            beacon: address(relayer),
            callData: "",
            immutableArgs: ""
        });
        assertEq(predicted, deployed);
    }

    // Deployment helpers in registry: detect deleted expressions
    function test_deployVerifiableUpgradeableBeacon_setsImplAndOwner_full() public {
        address implOwner = makeAddr("implOwner");
        MockImplementation impl = new MockImplementation();
        vm.prank(deployer);
        address addr =
            registry.deployVerifiableUpgradeableBeacon(uint96(111), implOwner, address(impl));
        VerifiableUpgradeableBeacon b = VerifiableUpgradeableBeacon(addr);
        (address currentImpl, uint256 cnt) = b.implementationAndCounter();
        assertEq(currentImpl, address(impl));
        assertEq(cnt, 2);
        assertEq(b.owner(), implOwner);
    }

    function test_deployVerifiableBeaconRelayer_setsBeaconAndOwner_full() public {
        address relayerOwner = makeAddr("relayerOwner");
        MockImplementation impl = new MockImplementation();
        VerifiableUpgradeableBeacon beacon =
            _deployVerifiableBeacon(address(this), address(impl), 5);
        vm.prank(deployer);
        address addr = registry.deployVerifiableUpgradeableBeaconRelayer(
            uint96(222), relayerOwner, address(beacon)
        );
        VerifiableBeaconRelayer r = VerifiableBeaconRelayer(addr);
        (address currentBeacon, uint256 cnt) = r.beaconAndCounter();
        assertEq(currentBeacon, address(beacon));
        assertEq(cnt, 2);
        assertEq(r.owner(), relayerOwner);
    }

}
