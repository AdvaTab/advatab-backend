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

In `read_write` mode the Durable Object MUST permit existing authenticated Phase 2 operations. In `read_only` mode it MUST permit pull, encrypted export, device listing, and security-reducing revocation, while blocking synchronized mutations, envelope writes, pairing, device additions, and other access-increasing writes.

#### Scenario: Read-only vault pulls encrypted data

- **WHEN** an authorized device performs an allowed pull or encrypted export in read-only mode
- **THEN** the request succeeds under the existing Phase 2 response contract

#### Scenario: Read-only vault attempts a mutation

- **WHEN** an authorized device attempts a sync mutation, pairing, envelope write, or access-increasing operation in read-only mode
- **THEN** the Durable Object rejects the operation without applying partial state

#### Scenario: Read-only vault revokes access

- **WHEN** an authorized security operation revokes a credential or device in read-only mode
- **THEN** the Durable Object permits the security-reducing revocation
- **AND** does not grant replacement or broader access as part of that operation

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
