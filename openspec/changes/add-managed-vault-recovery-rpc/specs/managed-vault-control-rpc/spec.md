## ADDED Requirements

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

## MODIFIED Requirements

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
