# Verifiable Beacons

![VerifiableBeacons](./media/verifiable_beacons.png)

Smart contracts and a small registry for deterministically deployed ERC-1967 beacon proxies with onchain verification against trusted beacon/relayer code and live state.

## The problem

Upgradeable smart contracts should be considered insecure by default. Even if _your_ protocol is immutable, a third party smart contract integration may not be. For added safety, you should be able to verify that the upgradeable smart contract your protocal integrates with has not been tampered with or upgraded to a malicious implementation.

In a normal upgradeable proxy smart contract, it's not possible to definitively know what implementation contract it currently points to. Adding an `implementation()` method to the proxy itself wouldn't help, because the proxy implementation can lie. Even then, it's not possible to know if it had been upgraded to a malicious or compromised implementation and then "upgraded" back to the known good implementation.

## The solution

### Prior art: BeaconProxies and UpgradeableBeacons

Beacon proxies point to an UpgradeableBeacon contract, which stores the current implementation address and returns it via the `implementation()` method. **How can we trust an UpgradeableBeacon's `implementation()` method?**

Because BeaconProxies hardcode the "beacon" address into their bytecode, when deployed deterministically via CREATE2, it's possible to verify that a beacon proxy 1. **is definitively** a beacon proxy and 2. the proxy points to a particular address **that will not change**.

From there, it's possible to verify that the UpgradeableBeacon it points to **is definitively** a "safe" UpgradeableBeacon by verifying its `EXTCODEHASH` matches the code hash of a known trusted implementation.

### VerifiableUpgradeableBeacon

VerifiableUpgradeableBeacons, a new implementation included in this repository, are upgradeable beacons that introduce a `counter` that increments with each upgrade. This makes it possible both to verify that the beacon points to a known and trusted implementation, _and_ that the beacon hasn't been tampered with by verifying that the current `counter` matches the expected value.

### VerifiableBeaconRegistry

The VerifiableBeaconRegistry is a small registry that allows `integrator` smart contracts (and their `owner()`s) to register trusted beacon (and relayer, more on that below) implementations for beacon proxies.

This repo provides:

-   Deterministic deployment helpers for a verifiable beacons and a verifiable beacon relayers.
-   A small registry that:
    -   Pins proxy derivation parameters and verifies beacon/relayer `EXTCODEHASH`.
    -   Lets each integrator record the trusted live state they will accept.
    -   Verifies at call time that current state still matches registered expectations.

## Components

-   `VerifiableUpgradeableBeacon`:

    -   Minimal, gas‑efficient beacon with packed storage for `(implementation, counter)`.
    -   `counter` increments on each upgrade; used for precise state pinning.
    -   Ownership baked in; `onlyOwner` can `upgradeTo`, `transferOwnership`, `renounceOwnership`.

-   `VerifiableBeaconRelayer`:

    -   Points to a beacon and exposes that beacon’s current `implementation()` to proxies.
    -   Tracks `(beacon, counter)` and increments the counter on each beacon change.
    -   Enables a two‑tier trust model: you can pin both the relayer state and the underlying beacon’s implementation state.

-   `VerifiableBeaconRegistry`:
    -   Records a deterministic beacon proxy’s target as either a beacon or a relayer, after verifying:
        -   The proxy address matches `CREATE2` derivation with the provided deployer and salt.
        -   The target’s runtime bytecode matches the trusted extcodehash of our beacon/relayer implementations.
    -   Per‑integrator, stores “trusted live state” and verifies against live state, not proxy storage:
        -   For proxies targeting a beacon: current `(implementation, counter)` must match what the integrator registered.
        -   For proxies targeting a relayer: current `(beacon, relayerCounter)` and the underlying beacon’s `(implementation, beaconCounter)` must match what the integrator registered.

## How verification works

-   The registry hardcodes (at deploy) the `extcodehash` of `VerifiableUpgradeableBeacon` and `VerifiableBeaconRelayer` runtime bytecode (computed as `keccak256(type(Contract).runtimeCode)`). Targets must match exactly.
-   Registration stores immutable proxy derivation parameters and the target address; verification later reads live state from the target(s):
    -   Beacon: `implementationAndCounter()`.
    -   Relayer: `beaconAndCounter()` then calls underlying beacon’s `implementationAndCounter()`.
-   Integrators (or their `owner()`) set the trusted state. Calls to `verifyImplementation(...)` return true only when current live state equals the integrator’s registered state.
-   The registry never interrogates the proxy itself; it verifies determinism (CREATE2 address) and reads state from the registered target(s). The beacon address inside the proxy is immutable per ERC‑1967/OpenZeppelin `BeaconProxy`.

## Deterministic deployment and prediction

-   The registry deploys beacons/relayers with CREATE2 and salts namespaced by the caller:
    -   Beacon: `deployVerifiableUpgradeableBeacon(uint96 salt, address initialOwner, address initialImplementation)`.
    -   Relayer: `deployVerifiableUpgradeableBeaconRelayer(uint96 salt, address initialOwner, address initialBeacon)`.
-   Address prediction utilities mirror the exact construction:
    -   `predictVerifiableUpgradeableBeaconAddress(address caller, uint96 salt)`.
    -   `predictVerifiableBeaconRelayerAddress(address caller, uint96 salt)`.
-   For proxies, the expected CREATE2 proxy address is derived via `deriveBeaconProxyAddress(deployer, salt, beaconOrRelayer)` and must match at registration.

## Typical integrator flow

1. Deploy trusted beacon (and optionally relayer) deterministically via the registry helpers.
2. Deploy the ERC‑1967 beacon proxy deterministically with your chosen factory and the same target.
3. Register the proxy with the registry:
    - Beacon target: `registerVerifiedBeaconProxy(proxy, deployer, salt, beacon)`.
    - Relayer target: `registerVerifiedBeaconRelayerProxy(proxy, deployer, salt, relayer)`.
4. Record trusted live state (per integrator):
    - Beacon: `registerTrustedBeaconImplementation(integrator, proxy, implementation, counter)`.
    - Relayer: `registerTrustedBeaconRelayerImplementation(integrator, proxy, beacon, relayerCounter, implementation, beaconCounter)`.
5. At integration points, call `verifyImplementation(proxy)` (or `verifyImplementation(integrator, proxy)`) and proceed only if true.

Notes:

-   Authorization for registering trusted state: caller must be the `integrator` or `Ownable(integrator).owner()`.
-   The registry never reads proxy storage; it always reads live state from the registered target(s).

## Security model and constraints

-   Extcodehash pinning: The target must have the exact trusted runtime bytecode. If you alter the beacon/relayer implementation bytecode, you must redeploy the registry or otherwise change the trust anchor.
-   State equality, not ranges: Verification checks for equality of current state against registered tuples. If any element changes (e.g., counter increments on upgrade), verification returns false until you re‑register new trusted values.
-   Determinism: Registration asserts that the proxy address equals the derived address for `(deployer, salt, beaconOrRelayer)`.
-   Ownership: Beacons and relayers are ownable; only the owner can upgrade. The registry transfers ownership to your `initialOwner` during helper deployment.

## Examples (sketch)

```solidity
// Deploy trusted beacon and proxy, then verify
VerifiableBeaconRegistry reg = new VerifiableBeaconRegistry();

// 1) Deploy beacon
address beacon = reg.deployVerifiableUpgradeableBeacon(0, address(this), address(impl));

// 2) Deploy deterministic proxy using your factory
address proxy = DeterministicProxyFactory(DETERMINISTIC_PROXY_FACTORY_ADDRESS).deployBeaconProxy({
  salt: bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
  beacon: beacon,
  callData: "",
  immutableArgs: ""
});

// 3) Register the proxy and target
reg.registerVerifiedBeaconProxy(
  proxy,
  DETERMINISTIC_PROXY_FACTORY_ADDRESS,
  bytes32(uint256(uint160(address(this))) << 96 | uint96(0)),
  beacon
);

// 4) Record trusted state for this integrator
(address implNow, uint256 counterNow) = VerifiableUpgradeableBeacon(beacon).implementationAndCounter();
reg.registerTrustedBeaconImplementation(address(this), proxy, implNow, counterNow);

// 5) Verify before interacting
bool ok = reg.verifyImplementation(proxy);
require(ok, "untrusted");
```

Relayer variant is analogous but pins `(beacon, relayerCounter, implementation, beaconCounter)`. See the dedicated "VerifiableBeaconRelayer (advanced)" section below for the relayer sketch.

## Development

-   Requirements: Foundry (see `foundry.toml`), dependencies vendored under `dependencies/`.
-   Build:
    -   `just build`
-   Test:
    -   `just test`
-   Mutation testing (Gambit):
    -   Generate and run: `just gambit-full` or incremental `just gambit-test`
    -   Report: `just gambit-report`

## Key contract methods

-   Registry

    -   Registration: `registerVerifiedBeaconProxy`, `registerVerifiedBeaconRelayerProxy`
    -   Trusted state: `registerTrustedBeaconImplementation`, `registerTrustedBeaconRelayerImplementation`
    -   Verification: `verifyImplementation(address)`, `verifyImplementation(address,address)`
    -   Deployment helpers: `deployVerifiableUpgradeableBeacon`, `deployVerifiableUpgradeableBeaconRelayer`
    -   Address tools: `predictVerifiableUpgradeableBeaconAddress`, `predictVerifiableBeaconRelayerAddress`, `deriveBeaconProxyAddress`

-   Beacon

    -   `upgradeTo`, `owner`, `transferOwnership`, `renounceOwnership`
    -   `implementationAndCounter()` returns `(implementation, counter)`

-- Relayer (advanced) - `upgradeTo` (sets new beacon), `owner`, `transferOwnership`, `renounceOwnership` - `beaconAndCounter()` returns `(beacon, counter)` - `implementation()` fetches current implementation from the configured beacon

## Caveats

-   Extcodehash trust anchors are for the specific runtime bytecode compiled into this repo; if you need to support multiple versions, you’ll need a higher‑level wrapper or separate registries.
-   Verification is read‑only; it doesn’t block calls. Your integration must gate behavior on `verifyImplementation(...)`.
-   The registry stores per‑proxy, per‑integrator records. If you rotate proxies or targets, you must re‑register and re‑verify.

## VerifiableBeaconRelayer (advanced)

Business context: We deploy many instances of the same product (e.g., stablecoins) for different customers and want to be able to upgrade them all at once. Beacon proxies are great for that. However, some customers will want the option to fully own their smart contracts. With a direct proxy → beacon setup, we (as beacon owner) would control upgrades for all instances; handing over one instance’s upgrade rights isn’t possible without handing over the beacon for all.

Normally, the solution would be to use a UUPSUpgradeableProxy -> BeaconProxy Implementation -> UpgradeableBeacon chain - but this is not verifiable.

The VerifiableBeaconRelayer solves this by matching the UpgradeableBeacon interface, but passing the `implementation()` call through to its own underlying beacon::

-   BeaconProxies target a relayer address
-   The relayer points to a beacon (e.g.) we operate, so we can upgrade all instances together at first.
-   Later, we can “break the link” by upgrading the relayer for a specific customer to point to a new beacon that they own. From that point on, they can upgrade their instance independently. The registry still verifies:
    -   the relayer’s `(beacon, relayerCounter)`, and
    -   the customer-owned beacon’s `(implementation, beaconCounter)`
        so integrators can continue to trust interactions.

Sketch:

```solidity
// Deploy a beacon, then a relayer pointing to it
address beacon = reg.deployVerifiableUpgradeableBeacon(0, address(this), address(impl));
address relayer = reg.deployVerifiableUpgradeableBeaconRelayer(0, address(this), beacon);

// Deploy proxy to relayer, register, and record trusted tuples (see earlier sections)
// Later, when handing off to the company:
address companyBeacon = reg.deployVerifiableUpgradeableBeacon(1, companyOwner, address(impl));
VerifiableBeaconRelayer(relayer).upgradeTo(companyBeacon); // hand off at the relayer layer
```

## Questions

-   Do you want the registry deployed once per environment, or per‑application (to allow different extcodehash baselines)?
-   Should we expose an optional role‑based auth (beyond `owner()`) for registering trusted state on behalf of integrators?
-   Do you also want a minimal helper for deploying the deterministic beacon proxy itself, or will you always use an external factory?

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this repository except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
