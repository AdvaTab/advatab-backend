# Managed Vault Control RPC Specification

## Purpose

Defines internal Durable Object RPCs for managed-vault initialization and monotonic effective-entitlement enforcement without changing the public Phase 2 protocol.

## Requirements

### Requirement: Initialize a managed vault through typed Durable Object RPC

The existing backend-owned `VaultDurableObject` MUST expose a typed `initializeManagedVault` RPC accepting `operationId`, client-generated `vaultId`, a verified public passkey credential, a first DeviceAuth public identity, and an effective entitlement. It MUST atomically persist the managed-vault identity, credential, device, effective entitlement, and operation result before returning `status`, its own `vaultHandle`, and `entitlementVersion`.

#### Scenario: First initialization succeeds

- **WHEN** customer-management invokes `initializeManagedVault` on the reserved Durable Object with valid first-device inputs
- **THEN** the object stores exactly one managed vault identity, credential, device, and effective entitlement
- **AND** returns its routing handle and persisted entitlement version

#### Scenario: Initialization contains no secrets or business metadata

- **WHEN** the RPC request is inspected
- **THEN** it contains public credential/device material, opaque identifiers, and effective access state only
- **AND** it contains no AccountKey, recovery secret, PRF output, device private key, contact email, invite source, subscription identity, or synchronized plaintext

### Requirement: Make control RPC operations idempotent and conflict-safe

Each control RPC MUST persist its method, operation ID, immutable-input identity, and result. An identical retry MUST return the stored result. Reuse of an operation ID with different immutable inputs or for a different method MUST return a conflict without changing vault state.

#### Scenario: Initialization response is lost

- **WHEN** initialization committed but its response was lost
- **AND** the caller repeats the identical request with the same operation ID
- **THEN** the object returns the stored result
- **AND** it does not duplicate or replace the credential, device, vault identity, or entitlement

#### Scenario: Operation ID is reused with different input

- **WHEN** a caller reuses an existing operation ID with changed immutable input
- **THEN** the RPC returns a conflict
- **AND** the previously persisted state and result remain unchanged

#### Scenario: New operation cannot reinitialize a different vault

- **WHEN** an initialized object receives a different operation ID containing a different `vaultId`, first credential, or first device
- **THEN** initialization returns a conflict
- **AND** the original managed vault identity remains authoritative

### Requirement: Apply only monotonic effective entitlement updates

The Durable Object MUST expose `setEffectiveEntitlement` accepting `operationId`, `product`, `tier`, `mode`, `validUntil`, and `version`. It MUST persist only the effective state and MUST NOT store entitlement history or source. A higher version MUST replace the current effective state, a lower version MUST be ignored, and an equal version MUST succeed only when its payload is identical.

#### Scenario: Newer effective state is applied

- **WHEN** an update has a version greater than the stored version
- **THEN** the object persists the new effective state and operation result before returning
- **AND** reports the new entitlement version

#### Scenario: Older version arrives late

- **WHEN** an update has a version lower than the stored version
- **THEN** the object leaves the newer state unchanged
- **AND** reports that the older update was not applied

#### Scenario: Equal version has a different payload

- **WHEN** an update uses the current version with different tier, mode, product, or validity
- **THEN** the object returns a conflict
- **AND** does not overwrite the current state

### Requirement: Enforce entitlement expiry locally

The Durable Object MUST evaluate `validUntil` locally for each authenticated data-plane operation. A null validity MUST be indefinite. Once a finite validity has passed, the object MUST enforce read-only behavior without waiting for D1 or a reconciliation RPC.

#### Scenario: Entitlement expires during control-plane outage

- **WHEN** `validUntil` passes while customer-management or D1 is unavailable
- **THEN** the Durable Object changes effective enforcement to read-only using its stored state and current time
- **AND** routine request handling does not query D1

### Requirement: Enforce explicit read-write and read-only policies

In `read_write` mode the Durable Object MUST permit existing authenticated Phase 2 operations. In `read_only` mode it MUST permit pull, encrypted export, device listing, security-reducing revocation, the cryptographically authenticated pairing lifecycle, managed passkey verification, and customer-management-authorized recovery-device enrollment. It MUST block synchronized mutations, ordinary envelope writes, and other data- or entitlement-increasing writes. A device added through pairing or recovery MUST remain subject to the same vault-wide read-only policy.

#### Scenario: Read-only vault pulls encrypted data

- **WHEN** an authorized device performs an allowed pull or encrypted export in read-only mode
- **THEN** the request succeeds under the existing Phase 2 response contract

#### Scenario: Read-only owner restores access

- **WHEN** an authenticated existing device approves pairing or customer-management authorizes recovery in read-only mode
- **THEN** the new device is registered and may pull or export encrypted data
- **AND** it receives no permission to mutate synchronized content

#### Scenario: Read-only vault attempts a mutation

- **WHEN** an authorized device attempts a sync mutation, ordinary envelope write, or other data-increasing operation in read-only mode
- **THEN** the Durable Object rejects the operation without applying partial state

#### Scenario: Read-only vault revokes access

- **WHEN** an authorized security operation revokes a credential or device in read-only mode
- **THEN** the Durable Object permits the security-reducing revocation
- **AND** does not grant replacement or broader write access as part of that operation

### Requirement: Preserve the Phase 2 public wire contract

Managed control RPCs MUST NOT change the request fields, response fields, signature profile, authentication method, or semantics of existing public `/v1/*` endpoints. The RPCs MUST remain an internal Cloudflare binding surface rather than a public bearer API.

#### Scenario: Existing signed sync remains compatible

- **WHEN** an existing extension or compatible custom client uses the Phase 2 sync API
- **THEN** it continues to use the existing signed-device protocol and payloads
- **AND** no customer, billing, invite, or entitlement-source field is required

#### Scenario: Backend remains independent of D1

- **WHEN** the backend routes or processes a managed Phase 2 request
- **THEN** it uses Durable Object-local identity and effective access state
- **AND** it does not query customer-management D1

### Requirement: Verify a managed passkey assertion through typed RPC

The existing `VaultDurableObject` MUST expose a typed `verifyManagedPasskey` RPC accepting an operation ID, WebAuthn challenge, expected RP ID and origin, and authentication assertion. It MUST verify the assertion against the stored managed credential, require user presence and user verification, require the returned user handle to equal the object's 32-byte routing handle, enforce signature-counter rules, and persist the updated counter and operation result before returning the handle, protocol version, and effective entitlement.

#### Scenario: Valid discoverable assertion succeeds

- **WHEN** the routed managed vault receives a valid assertion from its stored credential with the expected ceremony context and user handle
- **THEN** it records the credential counter and returns a verified result for its own vault handle

#### Scenario: Assertion targets another vault

- **WHEN** the credential ID, signature, or user handle does not match the routed object
- **THEN** the RPC rejects the assertion without returning vault metadata or changing the credential counter

#### Scenario: Verified response is lost

- **WHEN** verification committed but its response was lost and the identical operation is retried
- **THEN** the object returns the stored result without applying counter validation twice

### Requirement: Recover a managed device through typed RPC

The existing `VaultDurableObject` MUST expose `recoverManagedDevice` accepting an operation ID, positive recovery generation, and new DeviceAuth public identity. It MUST require an initialized managed vault and an encrypted recovery envelope for that generation, validate the device public key, and atomically persist the device and operation result before returning the existing `vaultId`, its own `vaultHandle`, registered device ID, encrypted recovery envelope, protocol version, and effective entitlement.

#### Scenario: Authorized recovery enrolls a device

- **WHEN** customer-management invokes recovery with an available generation and unused valid device identity
- **THEN** the object registers exactly one device and returns that generation's encrypted recovery envelope
- **AND** no vault, passkey, entitlement, or AccountKey identity changes

#### Scenario: Recovery retries after a lost response

- **WHEN** device enrollment committed and the identical operation is retried
- **THEN** the object returns the stored envelope and identity result
- **AND** does not insert another device

#### Scenario: Device ID conflicts

- **WHEN** recovery supplies an existing device ID with a different public key
- **THEN** the RPC returns a conflict without replacing the registered key

#### Scenario: Recovery generation is unavailable

- **WHEN** recovery names a generation that has no durable encrypted envelope
- **THEN** the RPC rejects before registering the device

### Requirement: Store immutable managed recovery-envelope generations

The Durable Object MUST retain positive, versioned encrypted recovery-envelope generations for managed recovery. The first signed managed recovery-envelope upload MUST make generation `1` available. Typed control RPC MUST allow an authenticated control-plane saga to store a higher generation and to test generation availability. A stored generation MUST be immutable: identical content is idempotent and different content for the same generation conflicts. When upgrading a managed vault created before this generation table existed, the object MUST lazily materialize generation `1` from its existing `key_envelopes` rows before answering generation-`1` availability or recovery requests and before storing a higher generation. It MAY accept duplicate legacy rows only when every `recovery-v1` candidate has crypto version `1`, non-empty nonce and ciphertext, and byte-identical content; malformed or conflicting candidates MUST leave generation `1` unavailable and fail closed.

#### Scenario: Initial managed envelope becomes generation one

- **WHEN** the first registered device uploads `recovery-v1` successfully
- **THEN** managed recovery generation `1` becomes available with the same ciphertext

#### Scenario: Replacement generation is staged

- **WHEN** customer-management stores a higher generation with a new encrypted envelope
- **THEN** the object persists it before acknowledging the operation
- **AND** retains prior generations until safe cleanup

#### Scenario: Generation is reused with different ciphertext

- **WHEN** a caller attempts to store different envelope content under an existing generation
- **THEN** the RPC returns a conflict and preserves the original envelope

#### Scenario: Legacy generation one is backfilled

- **WHEN** a managed vault created before this change has one or more identical `recovery-v1` rows in `key_envelopes` and generation `1` has not yet been materialized
- **THEN** the object stores that ciphertext as immutable generation `1` before reporting it available or storing a higher generation

#### Scenario: Conflicting legacy envelopes fail closed

- **WHEN** legacy `recovery-v1` rows contain malformed or different nonce/ciphertext content
- **THEN** generation `1` remains unavailable and the object does not select a candidate or stage another generation through the same control operation
