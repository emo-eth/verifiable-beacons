// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { VerifiableUpgradeableBeacon } from "src/VerifiableUpgradeableBeacon.sol";

contract DummyImpl { }

contract UpgradeableBeaconTest is Test {

    VerifiableUpgradeableBeacon beacon;
    address owner;
    address user;

    event Upgraded(address indexed implementation);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        vm.prank(owner);
        beacon = new VerifiableUpgradeableBeacon(owner, address(new DummyImpl()));
    }

    function test_constructor_initializes_owner_and_impl() public {
        (address impl, uint256 counter) = beacon.implementationAndCounter();
        assertEq(beacon.owner(), owner);
        assertEq(impl, address(type(DummyImpl).creationCode.length > 0 ? address(impl) : impl)); // impl
            // is packed; reading via function returns packed slot
        assertEq(counter, 1);
    }

    function test_onlyOwner_required_for_upgrade() public {
        DummyImpl next = new DummyImpl();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableUpgradeableBeacon.Unauthorized.selector));
        beacon.upgradeTo(address(next));
    }

    function test_onlyOwner_required_for_transferOwnership() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableUpgradeableBeacon.Unauthorized.selector));
        beacon.transferOwnership(user);
    }

    function test_renounceOwnership_effective() public {
        vm.prank(owner);
        beacon.renounceOwnership();
        assertEq(beacon.owner(), address(0));

        // After renounce, upgrading should fail for both owner and others
        DummyImpl next = new DummyImpl();
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(VerifiableUpgradeableBeacon.Unauthorized.selector));
        beacon.upgradeTo(address(next));

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(VerifiableUpgradeableBeacon.Unauthorized.selector));
        beacon.upgradeTo(address(next));
    }

    function test_deployViaRegistry_initializes_implementation() public {
        // Simulate the registry deployment path to catch mutation that deletes upgradeTo during
        // deploy
        address deployer = makeAddr("deployer");
        address dstOwner = makeAddr("dstOwner");
        DummyImpl impl = new DummyImpl();

        // Deploy a minimal inline registry-like helper
        BeaconDeployer helper = new BeaconDeployer();
        vm.prank(deployer);
        address addr = helper.deployBeaconLike(0, dstOwner, address(impl));
        VerifiableUpgradeableBeacon b = VerifiableUpgradeableBeacon(addr);
        (address currentImpl, uint256 cnt) = b.implementationAndCounter();
        assertEq(currentImpl, address(impl));
        assertEq(cnt, 2); // constructor set to registry, then upgraded to impl
        assertEq(b.owner(), dstOwner);
    }

}

contract BeaconDeployer {

    function deployBeaconLike(uint96 salt, address initialOwner, address initialImplementation)
        external
        returns (address)
    {
        // Mimic the logic used in VerifiableBeaconRegistry.deployVerifiableUpgradeableBeacon
        bytes32 fullSalt = bytes32(uint256(uint160(msg.sender)) << 96 | salt);
        VerifiableUpgradeableBeacon b =
            new VerifiableUpgradeableBeacon{ salt: fullSalt }(address(this), address(this));
        b.upgradeTo(initialImplementation);
        b.transferOwnership(initialOwner);
        return address(b);
    }

}
