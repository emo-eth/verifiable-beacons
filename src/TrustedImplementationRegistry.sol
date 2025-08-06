// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Ownable } from "solady/auth/Ownable.sol";
import { LibClone } from "solady/utils/LibClone.sol";

import { UpgradeableBeacon } from "src/UpgradeableBeacon.sol";

contract TrustedImplementationRegistry {

    /// @notice Thrown when the caller is not the integrator or the owner of the integrator
    error OnlyCallerOrOwner();
    /// @notice Thrown when a beacon proxy address does not match the derived address
    error BeaconProxyAddressMismatch();
    /// @notice Thrown when a beacon proxy is not registered
    error BeaconProxyNotRegistered();
    /// @notice Thrown when a beacon implementation extcodehash does not match the trusted value
    error BeaconImplementationExtcodehashMismatch();

    /// @notice The permissioned, deterministic proxy factory address this registry uses in address
    /// derivation
    address public immutable DETERMINISTIC_PROXY_FACTORY;
    /// @notice The extcodehash of the particular trusted UpgradeableBeacon implementation
    bytes32 public immutable UPGRADEABLE_BEACON_EXTCODEHASH;

    /// @notice mapping of trusted proxy implementations
    mapping(
        address integrator
            => mapping(address proxy => mapping(address implementation => uint256 counter))
    ) public trustedProxyImplementations;
    /// @notice mapping of verified deterministic beacon proxies to their verified beacon
    /// implementations
    mapping(address proxy => address beacon) public beacons;

    modifier onlyCallerOrOwner(address caller) {
        require(msg.sender == caller || Ownable(caller).owner() == msg.sender, OnlyCallerOrOwner());
        _;
    }

    constructor(address deterministicProxyFactory) {
        DETERMINISTIC_PROXY_FACTORY = deterministicProxyFactory;
        UPGRADEABLE_BEACON_EXTCODEHASH = keccak256(type(UpgradeableBeacon).runtimeCode);
    }

    function registerBeaconProxy(address beaconProxy, address deployer, uint96 salt, address beacon)
        public
    {
        // check that the beaconProxy is a deterministic beacon proxy
        address derivedBeaconProxyAddress = deriveBeaconProxyAddress(deployer, salt, beacon);
        require(derivedBeaconProxyAddress == beaconProxy, BeaconProxyAddressMismatch());

        // check that the beacon is the trusted beacon implementation
        bytes32 beaconExtcodehash = address(beacon).codehash;
        require(
            beaconExtcodehash == UPGRADEABLE_BEACON_EXTCODEHASH,
            BeaconImplementationExtcodehashMismatch()
        );

        // register the beacon proxy
        beacons[beaconProxy] = beacon;
    }

    function registerTrustedBeaconImplementation(
        address integrator,
        address proxy,
        address implementation,
        uint256 counter
    ) public onlyCallerOrOwner(integrator) {
        address beacon = beacons[proxy];
        require(beacon != address(0), BeaconProxyNotRegistered());
        trustedProxyImplementations[integrator][proxy][implementation] = counter;
    }

    function deriveBeaconProxyAddress(address deployer, uint96 salt, address beacon)
        public
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddressERC1967BeaconProxy({
            beacon: beacon,
            salt: bytes32(uint256(uint160(deployer)) << 96 | salt),
            deployer: DETERMINISTIC_PROXY_FACTORY
        });
    }

    function checkProxy(address proxy) public view returns (bool) {
        return checkProxy(msg.sender, proxy);
    }

    function checkProxy(address integrator, address proxy) public view returns (bool) {
        // get current implementation
        address beacon = beacons[proxy];
        (address currentImplementation, uint256 currentCounter) =
            UpgradeableBeacon(beacon).implementationAndCounter();

        return
            trustedProxyImplementations[integrator][proxy][currentImplementation] == currentCounter;
    }

    function deployUpgradeableBeacon(
        uint96 salt,
        address initialOwner,
        address initialImplementation
    ) public returns (address) {
        // encode caller in salt
        bytes32 fullSalt = bytes32(uint256(uint160(msg.sender)) << 96 | salt);

        // deploy beacon with salt with the same owner and implementation
        // regardless of params to keep the create2 address predictable
        UpgradeableBeacon beacon =
            new UpgradeableBeacon{ salt: fullSalt }(address(this), address(this));
        // upgrade to the initial implementation
        beacon.upgradeTo(initialImplementation);
        // transfer ownership
        beacon.transferOwnership(initialOwner);
        // return the beacon address
        return address(beacon);
    }

    function predictUpgradeableBeaconAddress(address caller, uint96 salt)
        external
        view
        returns (address)
    {
        // encode full initcode with constructor args
        bytes memory initcode = abi.encodePacked(
            type(UpgradeableBeacon).creationCode, abi.encode(address(this), address(this))
        );
        // get initcode hash
        bytes32 initcodeHash = keccak256(initcode);
        // encode full salt with caller
        bytes32 fullSalt = bytes32(uint256(uint160(caller)) << 96 | salt);
        address predicted;
        ///@solidity memory-safe-assembly
        assembly {
            // from solady
            mstore8(0x00, 0xff) // Write the prefix.
            mstore(0x35, initcodeHash)
            mstore(0x01, shl(96, address()))
            mstore(0x15, fullSalt)
            predicted := keccak256(0x00, 0x55)
            mstore(0x35, 0)
        }
        // no need to clean predicted since function is external only and will be cleaned when
        // copied to returndata
        return predicted;
    }

}
