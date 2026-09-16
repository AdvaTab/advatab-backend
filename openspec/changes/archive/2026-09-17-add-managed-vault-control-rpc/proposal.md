## Why

The managed customer service must provision and update the existing backend-owned `VaultDurableObject` without copying its implementation or coupling the Phase 2 data plane to D1. The backend therefore needs a small, typed, idempotent control-plane RPC surface while preserving every existing Phase 2 HTTP contract.

## What Changes

- Add a typed `initializeManagedVault` Durable Object RPC for first credential, first device, cryptographic vault identity, and initial effective entitlement state.
- Add a typed `setEffectiveEntitlement` RPC for monotonically versioned effective access updates.
- Make both methods idempotent by operation ID and reject operation-ID reuse with different immutable inputs.
- Persist initialization and effective entitlement state before acknowledging success.
- Enforce `read_write` and `read_only` modes locally in the vault without querying D1.
- Keep entitlement history, invite source, billing source, and customer contact data outside the Durable Object.
- Preserve all existing Phase 2 request/response formats and signed-device authentication behavior.

## Capabilities

### New Capabilities

- `managed-vault-control-rpc`: Typed, idempotent control-plane initialization and effective-entitlement updates for the backend-owned Vault Durable Object.

### Modified Capabilities

None. The existing encrypted sync wire contract remains unchanged.

## Impact

- Extends the existing backend `VaultDurableObject` with two public RPC methods and durable operation-result storage.
- Adds local enforcement of effective managed-cloud access state to existing mutation, pairing, read, export, device, and security-revocation paths.
- Provides the RPC type exported to the customer-management Worker through an external Durable Object namespace binding.
- Does not add D1, invitations, onboarding HTTP endpoints, billing logic, entitlement history, or client-side cryptography to this repository.
