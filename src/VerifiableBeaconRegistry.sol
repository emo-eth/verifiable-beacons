// SPDX-License-Identifier: Apache-2
pragma solidity ^0.8.20;

import { Ownable } from "solady/auth/Ownable.sol";
import { LibClone } from "solady/utils/LibClone.sol";

import { VerifiableBeaconRelayer } from "src/VerifiableBeaconRelayer.sol";
import { VerifiableUpgradeableBeacon } from "src/VerifiableUpgradeableBeacon.sol";

/// @title VerifiableBeaconRegistry
/// @notice Registry for deterministic ERC1967 beacon proxies that supports per-integrator
/// trusted implementations and onchain verification against trusted beacon relayer and/or beacon
/// state.
/// @dev
/// - Integrators are expected to be smart contracts; they must call in directly to register trusted
/// implementations or else their owner() must call.
/// - Registration records the proxy's deterministic parameters and pins trusted bytecode
///   (via EXTCODEHASH) for the target beacon or relayer.
/// - Verification checks the live state from the registered beacon/relayer; it does not
///   interrogate the proxy directly.
contract VerifiableBeaconRegistry {

    /**
     * @notice Stored info for a registered beacon proxy
     */
    struct BeaconProxyData {
        /// @notice True if the proxy targets a beacon relayer; false if it targets a beacon
        bool isRelayer;
        /// @notice The target address (beacon or beacon relayer)
        address beaconOrRelayer;
    }

    /**
     * @notice Per-integrator trusted info for a proxy pointing to a beacon relayer
     */
    struct TrustedBeaconRelayerData {
        /// @notice Trusted relayer upgrade counter
        uint96 relayerCounter;
        /// @notice Trusted beacon address behind the relayer
        address beacon;
        /// @notice Trusted beacon implementation upgrade counter
        uint96 beaconCounter;
        /// @notice Trusted beacon implementation address
        address implementation;
    }

    /// @notice Thrown when the caller is not the integrator or the owner of the integrator
    error OnlyCallerOrOwner();
    /// @notice Thrown when a beacon proxy address does not match the derived address
    error BeaconProxyAddressMismatch();
    /// @notice Thrown when a beacon proxy is not registered
    error BeaconProxyNotRegistered();
    /// @notice Thrown when a beacon relayer extcodehash does not match the trusted value
    error BeaconRelayerExtcodehashMismatch();
    /// @notice Thrown when a beacon implementation extcodehash does not match the trusted value
    error BeaconImplementationExtcodehashMismatch();
    /// @notice Thrown when a beacon has no code
    error BeaconHasNoCode();
    /// @notice Thrown when a beacon is not a beacon relayer
    error NotBeaconRelayer();

    /// @notice Emitted when a beacon proxy is verified
    event BeaconProxyVerified(address indexed proxy, address indexed beacon, bool isRelayer);
    /// @notice Emitted when a trusted beacon implementation is registered
    event TrustedBeaconImplementationRegistered(
        address indexed integrator, address indexed proxy, address implementation, uint256 counter
    );
    /// @notice Emitted when a trusted beacon relayer implementation is registered
    event TrustedBeaconRelayerImplementationRegistered(
        address indexed integrator,
        address indexed proxy,
        address beaconRelayer,
        uint96 relayerCounter,
        address implementation,
        uint96 beaconCounter
    );

    /// @notice The extcodehash of the particular trusted BeaconRelayer implementation
    bytes32 public immutable VERIFIABLE_BEACON_RELAYER_EXTCODEHASH;
    /// @notice The extcodehash of the particular trusted UpgradeableBeacon implementation
    bytes32 public immutable VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH;

    /// @notice mapping of verified deterministic beacon proxies to their verified beacon relayers
    mapping(address proxy => BeaconProxyData info) public beacons;
    /// @notice mapping of trusted beacon relayers and their counters
    mapping(
        address integrator
            => mapping(
                address proxy => mapping(address beaconRelayer => TrustedBeaconRelayerData info)
            )
    ) public verifiedBeaconRelayerImplementations;
    mapping(
        address integrator
            => mapping(address proxy => mapping(address implementation => uint256 counter))
    ) public verifiedBeaconImplementations;

    /**
     * @notice Restricts to the integrator contract or its owner.
     * @param caller The integrator contract address used for authorization.
     * @dev Authorization is granted if `msg.sender == caller` or
     *      `Ownable(caller).owner() == msg.sender`. Roles are not considered.
     */
    modifier onlyCallerOrOwner(address caller) {
        _onlyCallerOrOwner(caller);
        _;
    }

    /**
     * @dev Wrapped modifier implementation to minimize bytecode size.
     */
    function _onlyCallerOrOwner(address caller) internal view {
        // todo: handle roles too?
        require(msg.sender == caller || Ownable(caller).owner() == msg.sender, OnlyCallerOrOwner());
    }

    constructor() {
        VERIFIABLE_BEACON_RELAYER_EXTCODEHASH = keccak256(type(VerifiableBeaconRelayer).runtimeCode);
        VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH =
            keccak256(type(VerifiableUpgradeableBeacon).runtimeCode);
    }

    // ============================================================================
    // PUBLIC FUNCTIONS - BEACON PROXY REGISTRATION
    // ============================================================================

    /**
     * @notice Register a deterministic and immutable beacon proxy that targets a verifiable
     * upgradeable beacon.
     * @dev Idempotent if called with the same parameters. This verifies the trusted beacon bytecode
     *      via EXTCODEHASH and records the proxy's deterministic and immutable derivation. It does
     *      not read the proxy's current linkage.
     * @param beaconProxy The proxy address to register.
     * @param create2Deployer The deployer address used for the proxy's CREATE2 deployment.
     * @param salt The CREATE2 salt used for the proxy.
     * @param beacon The target beacon address (must match the trusted runtime bytecode).
     */
    function registerVerifiedBeaconProxy(
        address beaconProxy,
        address create2Deployer,
        bytes32 salt,
        address beacon
    ) public {
        // check that the beaconProxy is a deterministic beacon proxy
        address derivedBeaconProxyAddress = deriveBeaconProxyAddress(create2Deployer, salt, beacon);
        require(derivedBeaconProxyAddress == beaconProxy, BeaconProxyAddressMismatch());

        // check that the beacon is the trusted beacon implementation
        bytes32 beaconExtcodehash = address(beacon).codehash;
        require(
            beaconExtcodehash == VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH,
            BeaconImplementationExtcodehashMismatch()
        );

        // register the beacon proxy
        beacons[beaconProxy] = BeaconProxyData({ isRelayer: false, beaconOrRelayer: beacon });
        emit BeaconProxyVerified(beaconProxy, beacon, false);
    }

    /**
     * @notice Register a deterministic and immutable beacon proxy that targets a verifiable
     * beacon relayer.
     * @dev Idempotent if called with the same parameters. This verifies the trusted relayer
     *      bytecode via EXTCODEHASH and records the proxy's deterministic and immutable derivation.
     *      It does not read the proxy's current linkage.
     * @param beaconProxy The proxy address to register.
     * @param create2Deployer The deployer address used for the proxy's CREATE2 deployment.
     * @param salt The CREATE2 salt used for the proxy.
     * @param beaconRelayer The relayer address (must match the trusted runtime bytecode).
     */
    function registerVerifiedBeaconRelayerProxy(
        address beaconProxy,
        address create2Deployer,
        bytes32 salt,
        address beaconRelayer
    ) public {
        // check that the beaconProxy is a deterministic beacon proxy
        address derivedBeaconProxyAddress =
            deriveBeaconProxyAddress(create2Deployer, salt, beaconRelayer);
        require(derivedBeaconProxyAddress == beaconProxy, BeaconProxyAddressMismatch());

        // check that the beaconRelayer is the trusted beacon relayer implementation
        bytes32 beaconRelayerExtcodehash = address(beaconRelayer).codehash;
        require(
            beaconRelayerExtcodehash == VERIFIABLE_BEACON_RELAYER_EXTCODEHASH,
            BeaconRelayerExtcodehashMismatch()
        );

        // register the beacon proxy
        beacons[beaconProxy] = BeaconProxyData({ isRelayer: true, beaconOrRelayer: beaconRelayer });
        emit BeaconProxyVerified(beaconProxy, beaconRelayer, true);
    }

    // ============================================================================
    // PUBLIC FUNCTIONS - TRUSTED IMPLEMENTATION REGISTRATION
    // ============================================================================

    /**
     * @notice Record a trusted implementation for a registered beacon proxy for a specific
     * integrator.
     * @dev Only the integrator contract or its owner may call. The `counter` must match the
     *      beacon's current implementation counter when verification occurs.
     * @param integrator The integrator contract to register the trusted implementation for.
     * @param proxy The registered beacon proxy address.
     * @param implementation The trusted beacon implementation address.
     * @param counter The trusted beacon implementation counter.
     */
    function registerTrustedBeaconImplementation(
        address integrator,
        address proxy,
        address implementation,
        uint256 counter
    ) public onlyCallerOrOwner(integrator) {
        (, address beacon) = _getBeacon(proxy);
        require(beacon != address(0), BeaconProxyNotRegistered());
        verifiedBeaconImplementations[integrator][proxy][implementation] = counter;
        emit TrustedBeaconImplementationRegistered(integrator, proxy, implementation, counter);
    }

    /**
     * @notice Record trusted relayer and beacon state for a registered relayer proxy (per
     * integrator).
     * @dev Only the integrator contract or its owner may call. The provided values must match
     *      the live relayer's `(beacon, relayerCounter)` and the live beacon's
     *      `(implementation, beaconCounter)` at verification time. The `beacon` is checked
     *      to match the trusted beacon bytecode.
     * @param integrator The integrator contract to register the trusted implementation for.
     * @param proxy The registered relayer proxy address.
     * @param beacon The trusted beacon address behind the relayer.
     * @param relayerCounter The trusted relayer upgrade counter.
     * @param implementation The trusted beacon implementation address.
     * @param beaconCounter The trusted beacon implementation upgrade counter.
     */
    function registerTrustedBeaconRelayerImplementation(
        address integrator,
        address proxy,
        address beacon,
        uint96 relayerCounter,
        address implementation,
        uint96 beaconCounter
    ) public onlyCallerOrOwner(integrator) {
        (bool isRelayer, address relayer) = _getBeacon(proxy);
        require(relayer != address(0), BeaconProxyNotRegistered());
        require(isRelayer, NotBeaconRelayer());
        bytes32 beaconExtcodehash = address(beacon).codehash;
        require(
            beaconExtcodehash == VERIFIABLE_UPGRADEABLE_BEACON_EXTCODEHASH,
            BeaconImplementationExtcodehashMismatch()
        );
        verifiedBeaconRelayerImplementations[integrator][proxy][relayer] = TrustedBeaconRelayerData({
            relayerCounter: relayerCounter,
            beacon: beacon,
            beaconCounter: beaconCounter,
            implementation: implementation
        });
        emit TrustedBeaconRelayerImplementationRegistered(
            integrator, proxy, relayer, relayerCounter, implementation, beaconCounter
        );
    }

    // ============================================================================
    // PUBLIC FUNCTIONS - PROXY VERIFICATION
    // ============================================================================

    /**
     * @notice Verify, for the caller as integrator, that the proxy's current implementation is
     * trusted.
     * @dev Uses `msg.sender` as the integrator key. Reads live state from the registered
     *      beacon and/or relayer
     * @param proxy The registered beacon or relayer proxy.
     */
    function verifyImplementation(address proxy) public view returns (bool) {
        return verifyImplementation(msg.sender, proxy);
    }

    /**
     * @notice Verify, for a specific integrator, that the proxy's current implementation is
     * trusted.
     * @dev Reads live state from the registered beacon and/or relayer
     * @param integrator The integrator contract to verify the implementation for.
     * @param proxy The registered beacon or relayer proxy.
     */
    function verifyImplementation(address integrator, address proxy) public view returns (bool) {
        (bool isRelayer, address beacon) = _getBeacon(proxy);
        require(beacon != address(0), BeaconProxyNotRegistered());
        if (isRelayer) {
            return _verifyImplementationRelayer(integrator, proxy, beacon);
        } else {
            return _verifyImplementationBeacon(integrator, proxy, beacon);
        }
    }

    // ============================================================================
    // PUBLIC FUNCTIONS - BEACON DEPLOYMENT
    // ============================================================================

    /**
     * @notice Deploy a verifiable upgradeable beacon at a deterministic address.
     * @dev The deployed runtime bytecode is the trusted one used by the registry's EXTCODEHASH.
     *      The salt is namespaced by the caller. Ownership is transferred to `initialOwner`, and
     *      the beacon is upgraded to `initialImplementation` after deployment.
     * @param salt Caller-namespaced salt (lower 96 bits used).
     * @param initialOwner The initial owner to transfer to.
     * @param initialImplementation The initial implementation to set.
     */
    function deployVerifiableUpgradeableBeacon(
        uint96 salt,
        address initialOwner,
        address initialImplementation
    ) public returns (address) {
        // encode caller in salt
        bytes32 fullSalt = bytes32(uint256(uint160(msg.sender)) << 96 | salt);

        // deploy beacon with salt with the same owner and implementation
        // regardless of params to keep the create2 address predictable
        VerifiableUpgradeableBeacon beacon =
            new VerifiableUpgradeableBeacon{ salt: fullSalt }(address(this), address(this));
        // upgrade to the initial implementation
        beacon.upgradeTo(initialImplementation);
        // transfer ownership
        beacon.transferOwnership(initialOwner);
        // return the beacon address
        return address(beacon);
    }

    /**
     * @notice Deploy a verifiable beacon relayer at a deterministic address.
     * @dev The deployed runtime bytecode is the trusted one used by the registry's EXTCODEHASH.
     *      The salt is namespaced by the caller. Ownership is transferred to `initialOwner`, and
     *      the relayer is upgraded to `initialBeacon` after deployment.
     * @param salt Caller-namespaced salt (lower 96 bits used).
     * @param initialOwner The initial owner to transfer to.
     * @param initialBeacon The initial beacon to set on the relayer.
     */
    function deployVerifiableUpgradeableBeaconRelayer(
        uint96 salt,
        address initialOwner,
        address initialBeacon
    ) public returns (address) {
        // encode caller in salt
        bytes32 fullSalt = bytes32(uint256(uint160(msg.sender)) << 96 | salt);

        // deploy beacon relayer with salt with the same owner and beacon
        // regardless of params to keep the create2 address predictable
        VerifiableBeaconRelayer beaconRelayer =
            new VerifiableBeaconRelayer{ salt: fullSalt }(address(this), address(this));
        // upgrade to the initial beacon
        beaconRelayer.upgradeTo(initialBeacon);
        // transfer ownership
        beaconRelayer.transferOwnership(initialOwner);
        // return the beacon relayer address
        return address(beaconRelayer);
    }

    // ============================================================================
    // PUBLIC FUNCTIONS - ADDRESS PREDICTION
    // ============================================================================

    /**
     * @notice Predict the deterministic address for a beacon deployed by this registry.
     * @param caller The deployer whose address is namespaced into the salt.
     * @param salt The caller-provided 96-bit salt.
     */
    function predictVerifiableUpgradeableBeaconAddress(address caller, uint96 salt)
        external
        view
        returns (address)
    {
        // encode full initcode with constructor args
        // TODO: precompute initcodehash to reduce bytecode size
        bytes memory initcode = abi.encodePacked(
            type(VerifiableUpgradeableBeacon).creationCode, abi.encode(address(this), address(this))
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

    /**
     * @notice Predict the deterministic address for a beacon relayer deployed by this registry.
     * @param caller The deployer whose address is namespaced into the salt.
     * @param salt The caller-provided 96-bit salt.
     */
    function predictVerifiableBeaconRelayerAddress(address caller, uint96 salt)
        external
        view
        returns (address)
    {
        // encode full initcode with constructor args
        bytes memory initcode = abi.encodePacked(
            type(VerifiableBeaconRelayer).creationCode, abi.encode(address(this), address(this))
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

    /**
     * @notice Compute the deterministic address of an ERC1967 beacon proxy for a given target.
     * @param deployer The CREATE2 deployer address.
     * @param salt The CREATE2 salt used for the proxy deployment.
     * @param beacon The target address (beacon or relayer) used by the proxy.
     * @return The predicted proxy address.
     */
    function deriveBeaconProxyAddress(address deployer, bytes32 salt, address beacon)
        public
        pure
        returns (address)
    {
        return LibClone.predictDeterministicAddressERC1967BeaconProxy({
            beacon: beacon,
            salt: salt,
            deployer: deployer
        });
    }

    // ============================================================================
    // INTERNAL FUNCTIONS
    // ============================================================================

    function _getBeacon(address proxy) internal view returns (bool isRelayer, address beacon) {
        BeaconProxyData storage info = beacons[proxy];
        assembly {
            let slot := sload(info.slot)
            isRelayer := shr(248, shl(248, slot))
            beacon := shr(8, slot)
        }
    }

    function _verifyImplementationBeacon(address integrator, address proxy, address beacon)
        internal
        view
        returns (bool)
    {
        // get current implementation
        (address currentImplementation, uint256 currentCounter) =
            VerifiableUpgradeableBeacon(beacon).implementationAndCounter();

        return verifiedBeaconImplementations[integrator][proxy][currentImplementation]
            == currentCounter;
    }

    function _verifyImplementationRelayer(address integrator, address proxy, address relayer)
        internal
        view
        returns (bool)
    {
        // get current implementation from beacon relayer

        // Check that the relayer counter and beacon matches what was registered
        (address currentBeacon, uint256 currentBeaconRelayerCounter) =
            VerifiableBeaconRelayer(relayer).beaconAndCounter();
        TrustedBeaconRelayerData memory trustedInfo =
            verifiedBeaconRelayerImplementations[integrator][proxy][relayer];
        if (currentBeaconRelayerCounter != trustedInfo.relayerCounter) {
            return false;
        }
        if (currentBeacon != trustedInfo.beacon) {
            return false;
        }
        // get the current implementation and counter from the beacon
        (address currentImplementation, uint256 currentBeaconCounter) =
            VerifiableUpgradeableBeacon(currentBeacon).implementationAndCounter();
        if (currentImplementation != trustedInfo.implementation) {
            return false;
        }
        if (currentBeaconCounter != trustedInfo.beaconCounter) {
            return false;
        }
        return true;
    }

}
