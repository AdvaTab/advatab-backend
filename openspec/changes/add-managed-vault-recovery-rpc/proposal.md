## Why

The managed Vault Durable Object stores the authoritative passkey, device, recovery envelope, and encrypted vault state, but its control RPC currently supports only first-account initialization and entitlement updates. Returning customers need narrowly scoped, idempotent RPC operations that verify an existing passkey and enroll a recovered device without exposing secrets or changing the Phase 2 wire protocol.

## What Changes

- Add a typed RPC that verifies a WebAuthn authentication assertion against the credential stored in the target managed vault and updates its signature counter safely.
- Add a typed recovery RPC that idempotently registers one new DeviceAuth public key and returns the existing vault identity plus encrypted recovery envelope.
- Bind both operations to control-plane operation IDs and immutable-input digests so retries are safe and conflicting reuse is rejected.
- Allow authenticated pairing and recovery device enrollment while a managed vault is read-only; the resulting device remains subject to read-only sync enforcement.
- Keep recovery-code verifiers, recovery-session tokens, Customer data, contact email, and entitlement history out of Durable Object storage.
- Preserve all existing Phase 2 endpoints and managed initialization/entitlement RPC behavior.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `managed-vault-control-rpc`: Add passkey assertion verification and recovery-device enrollment/envelope retrieval, and refine read-only behavior for owner-authorized access restoration.

## Impact

- Extends the exported typed Durable Object RPC interface and Vault Durable Object implementation.
- Adds WebAuthn assertion validation, idempotency records, device-enrollment transactions, read-only policy tests, and companion contract fixtures.
- Is consumed only by customer-management through the external namespace binding; it does not add a second Durable Object or a public control API.
