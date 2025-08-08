// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.4;

import { Test } from "forge-std/Test.sol";
import { VerifiableBeaconRelayer } from "src/VerifiableBeaconRelayer.sol";

contract MockBeacon {

    address private _implementation;

    constructor(address implementation_) {
        _implementation = implementation_;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }

}

contract MockImplementation {

    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }

}

contract BeaconRelayerTest is Test {

    VerifiableBeaconRelayer public beaconRelayer;
    MockBeacon public mockBeacon;
    MockImplementation public mockImplementation;
    MockImplementation public mockImplementation2;

    address owner;
    address user;

    event BeaconUpgraded(address indexed beacon);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        mockImplementation = new MockImplementation();
        mockImplementation2 = new MockImplementation();
        mockBeacon = new MockBeacon(address(mockImplementation));

        vm.prank(owner);
        beaconRelayer = new VerifiableBeaconRelayer(owner, address(mockBeacon));
    }

    // ============================================================================
    // Constructor Tests
    // ============================================================================

    function test_constructor_success() public {
        vm.prank(owner);
        VerifiableBeaconRelayer newRelayer = new VerifiableBeaconRelayer(owner, address(mockBeacon));

        assertEq(newRelayer.owner(), owner);
        assertEq(newRelayer.beacon(), address(mockBeacon));
        assertEq(newRelayer.counter(), 1);
    }

    function test_constructor_withZeroOwner() public {
        VerifiableBeaconRelayer newRelayer =
            new VerifiableBeaconRelayer(address(0), address(mockBeacon));

        assertEq(newRelayer.owner(), address(0));
        assertEq(newRelayer.beacon(), address(mockBeacon));
        assertEq(newRelayer.counter(), 1);
    }

    function test_constructor_withZeroBeacon() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.NewBeaconHasNoCode.selector));
        VerifiableBeaconRelayer newRelayer = new VerifiableBeaconRelayer(owner, address(0));
    }

    // ============================================================================
    // Beacon Management Tests
    // ============================================================================

    function test_upgradeTo_success() public {
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));

        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit BeaconUpgraded(address(newBeacon));
        beaconRelayer.upgradeTo(address(newBeacon));

        assertEq(beaconRelayer.beacon(), address(newBeacon));
        assertEq(beaconRelayer.counter(), 2);
    }

    function test_upgradeTo_fail_Unauthorized() public {
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.Unauthorized.selector));
        beaconRelayer.upgradeTo(address(newBeacon));
    }

    function test_upgradeTo_fail_NewBeaconHasNoCode() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.NewBeaconHasNoCode.selector));
        beaconRelayer.upgradeTo(address(0x1234));
    }

    function test_upgradeTo_multipleUpgrades() public {
        MockBeacon newBeacon1 = new MockBeacon(address(mockImplementation2));
        MockBeacon newBeacon2 = new MockBeacon(address(mockImplementation));

        vm.startPrank(owner);

        beaconRelayer.upgradeTo(address(newBeacon1));
        assertEq(beaconRelayer.counter(), 2);

        beaconRelayer.upgradeTo(address(newBeacon2));
        assertEq(beaconRelayer.counter(), 3);

        vm.stopPrank();
    }

    // ============================================================================
    // Implementation Retrieval Tests
    // ============================================================================

    function test_implementation_success() public {
        address implementation = beaconRelayer.implementation();
        assertEq(implementation, address(mockImplementation));
    }

    function test_implementation_fail_UnableToRetrieveImplementation() public {
        // Deploy a beacon that doesn't have an implementation function
        MockImplementation badBeacon = new MockImplementation();

        vm.prank(owner);
        beaconRelayer.upgradeTo(address(badBeacon));

        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRelayer.UnableToRetrieveImplementation.selector)
        );
        beaconRelayer.implementation();
    }

    function test_implementation_fail_BeaconHasNoCode() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.NewBeaconHasNoCode.selector));
        beaconRelayer.upgradeTo(address(0x1234));
    }

    // ============================================================================
    // Counter Tests
    // ============================================================================

    function test_counter_initialValue() public {
        assertEq(beaconRelayer.counter(), 1);
    }

    function test_counter_afterUpgrade() public {
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));

        vm.prank(owner);
        beaconRelayer.upgradeTo(address(newBeacon));

        assertEq(beaconRelayer.counter(), 2);
    }

    function test_counter_multipleUpgrades() public {
        MockBeacon newBeacon1 = new MockBeacon(address(mockImplementation2));
        MockBeacon newBeacon2 = new MockBeacon(address(mockImplementation));

        vm.startPrank(owner);

        beaconRelayer.upgradeTo(address(newBeacon1));
        assertEq(beaconRelayer.counter(), 2);

        beaconRelayer.upgradeTo(address(newBeacon2));
        assertEq(beaconRelayer.counter(), 3);

        vm.stopPrank();
    }

    // ============================================================================
    // Beacon and Counter Tests
    // ============================================================================

    function test_beaconAndCounter_initialValues() public {
        (address beacon, uint256 counter) = beaconRelayer.beaconAndCounter();

        assertEq(beacon, address(mockBeacon));
        assertEq(counter, 1);
    }

    function test_beaconAndCounter_afterUpgrade() public {
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));

        vm.prank(owner);
        beaconRelayer.upgradeTo(address(newBeacon));

        (address beacon, uint256 counter) = beaconRelayer.beaconAndCounter();

        assertEq(beacon, address(newBeacon));
        assertEq(counter, 2);
    }

    // ============================================================================
    // Ownership Tests
    // ============================================================================

    function test_owner_initialValue() public {
        assertEq(beaconRelayer.owner(), owner);
    }

    function test_transferOwnership_success() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        beaconRelayer.transferOwnership(newOwner);

        assertEq(beaconRelayer.owner(), newOwner);
    }

    function test_transferOwnership_fail_Unauthorized() public {
        address newOwner = makeAddr("newOwner");

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.Unauthorized.selector));
        beaconRelayer.transferOwnership(newOwner);
    }

    function test_transferOwnership_fail_NewOwnerIsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRelayer.NewOwnerIsZeroAddress.selector)
        );
        beaconRelayer.transferOwnership(address(0));
    }

    function test_renounceOwnership_success() public {
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, address(0));
        beaconRelayer.renounceOwnership();

        assertEq(beaconRelayer.owner(), address(0));
    }

    function test_renounceOwnership_fail_Unauthorized() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.Unauthorized.selector));
        beaconRelayer.renounceOwnership();
    }

    // ============================================================================
    // Fuzz Tests
    // ============================================================================

    function testFuzz_upgradeTo_multipleBeacons(address[] calldata beaconAddresses) public {
        vm.assume(beaconAddresses.length > 0 && beaconAddresses.length <= 10);

        // Filter out addresses that don't have code
        for (uint256 i = 0; i < beaconAddresses.length; i++) {
            address beaconAddr = beaconAddresses[i];
            if (beaconAddr.code.length > 0) {
                vm.prank(owner);
                beaconRelayer.upgradeTo(beaconAddr);
            }
        }

        // Verify counter increased for each successful upgrade
        uint256 expectedCounter = 1;
        for (uint256 i = 0; i < beaconAddresses.length; i++) {
            if (beaconAddresses[i].code.length > 0) {
                expectedCounter++;
            }
        }

        assertEq(beaconRelayer.counter(), expectedCounter);
    }

    function testFuzz_transferOwnership(address newOwner) public {
        vm.assume(newOwner != address(0));

        vm.prank(owner);
        beaconRelayer.transferOwnership(newOwner);

        assertEq(beaconRelayer.owner(), newOwner);
    }

    // ============================================================================
    // Edge Cases and Integration Tests
    // ============================================================================

    function test_beaconRelayer_withProxyInteraction() public {
        // Test that the beacon relayer works correctly with proxy interactions
        address implementation = beaconRelayer.implementation();
        assertEq(implementation, address(mockImplementation));

        // Upgrade to a new beacon
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));
        vm.prank(owner);
        beaconRelayer.upgradeTo(address(newBeacon));

        // Verify the new implementation is returned
        address newImplementation = beaconRelayer.implementation();
        assertEq(newImplementation, address(mockImplementation2));
    }

    function test_storagePacking_integrity() public {
        // Test that the storage packing works correctly
        (address beacon, uint256 counter) = beaconRelayer.beaconAndCounter();

        // Verify the packed storage can be unpacked correctly
        assertEq(beacon, beaconRelayer.beacon());
        assertEq(counter, beaconRelayer.counter());
    }

    function test_multipleOwnershipTransfers() public {
        address newOwner1 = makeAddr("newOwner1");
        address newOwner2 = makeAddr("newOwner2");

        vm.startPrank(owner);
        beaconRelayer.transferOwnership(newOwner1);
        assertEq(beaconRelayer.owner(), newOwner1);
        vm.stopPrank();

        vm.startPrank(newOwner1);
        beaconRelayer.transferOwnership(newOwner2);
        assertEq(beaconRelayer.owner(), newOwner2);
        vm.stopPrank();
    }

    function test_beaconRelayer_afterOwnershipRenounce() public {
        vm.prank(owner);
        beaconRelayer.renounceOwnership();

        // Verify that no one can upgrade after ownership renounce
        MockBeacon newBeacon = new MockBeacon(address(mockImplementation2));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.Unauthorized.selector));
        beaconRelayer.upgradeTo(address(newBeacon));
    }

    // ============================================================================
    // Revert Tests
    // ============================================================================

    function test_revert_implementation_withInvalidBeacon() public {
        // Create a beacon that returns invalid data
        MockImplementation invalidBeacon = new MockImplementation();

        vm.prank(owner);
        beaconRelayer.upgradeTo(address(invalidBeacon));

        vm.expectRevert(
            abi.encodeWithSelector(VerifiableBeaconRelayer.UnableToRetrieveImplementation.selector)
        );
        beaconRelayer.implementation();
    }

    function test_revert_upgradeTo_withContractWithoutCode() public {
        // Try to upgrade to a contract that doesn't exist
        address nonExistentContract = address(0x1234567890123456789012345678901234567890);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VerifiableBeaconRelayer.NewBeaconHasNoCode.selector));
        beaconRelayer.upgradeTo(nonExistentContract);
    }

}
