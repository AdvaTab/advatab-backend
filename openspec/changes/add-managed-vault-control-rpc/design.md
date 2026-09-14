## Context

The backend already owns and exports the SQLite-backed `VaultDurableObject` that implements the open Phase 2 encrypted-sync protocol. Customer-management will own D1, invite onboarding, permanent Customer/CloudVault records, entitlement history, and the managed public gateway. It will bind to this backend-owned Durable Object namespace with an external `script_name` binding.

Provisioning crosses D1 and Durable Object storage without a distributed transaction. The backend therefore needs a deliberately small RPC boundary that can be retried after ambiguous failures. Routine `/v1/*` traffic must keep using the existing signed HTTP protocol and must not depend on D1.

## Goals / Non-Goals

**Goals:**

- Extend the existing Vault Durable Object rather than create a second managed implementation.
- Initialize exactly one cryptographic vault identity, first passkey credential, first device public key, and initial effective entitlement for a reserved Durable Object handle.
- Apply effective entitlement changes monotonically and idempotently.
- Persist every acknowledged control result before returning it.
- Enforce read/write versus read-only behavior locally.
- Preserve all Phase 2 request and response contracts.

**Non-Goals:**

- D1 schemas, Customer/CloudVault lifecycle, invite validation, WebAuthn ceremony verification, or onboarding HTTP APIs.
- Entitlement history, source precedence, billing state, contact email, or reconciliation scheduling.
- PRF, AccountKey recovery logic, fresh-device passkey login, or new encryption primitives.
- A second Durable Object class or a fork of the Phase 2 data plane.

## Decisions

### 1. Add typed RPC methods to the existing Durable Object

`VaultDurableObject` will expose:

```ts
initializeManagedVault({
  operationId,
  vaultId,
  credential,
  device,
  effectiveEntitlement,
}) => ({ status, vaultHandle, entitlementVersion })

setEffectiveEntitlement({
  operationId,
  product,
  tier,
  mode,
  validUntil,
  version,
}) => ({ applied, entitlementVersion })
```

The customer-management binding will be typed as `DurableObjectNamespace<VaultDurableObject>`. The caller reconstructs the reserved ID with `idFromString(vaultHandle)`, obtains the stub, and invokes these methods. The backend remains the only deployment that owns the Durable Object migration.

Using RPC avoids an internal HTTP protocol and makes the repository boundary explicit. A copied DO implementation was rejected because it would split schema ownership and Phase 2 behavior.

### 2. Persist idempotency by method and operation ID

Each RPC stores a record containing method, operation ID, a canonical hash of immutable inputs, and the serialized result. An identical retry returns the stored result. Reusing the same operation ID for another method or different immutable inputs throws a conflict.

The operation result and the state it acknowledges are committed before the RPC returns. Initialization also checks the permanent vault identity so a new operation ID cannot reinitialize an existing object with a different `vaultId`, first credential, or first device.

### 3. Treat initialization as a single local transaction

Initialization writes the managed-vault marker, `vaultId`, first credential, first device, initial effective entitlement, and operation result atomically in Durable Object SQLite. The DO obtains its own routing handle from `ctx.id.toString()` for the response; the caller does not supply a second handle value that could disagree with routing.

The RPC accepts only public credential/device material, opaque identifiers, and effective access state. It never accepts AccountKey, recovery secret, device private key, PRF output, entitlement source, billing metadata, or synchronized plaintext.

### 4. Version only effective entitlement state

The DO stores one effective record per supported product. A version lower than the current value is ignored. An equal version is accepted only when the entire effective payload is identical; otherwise it conflicts. A higher version replaces the effective state and records the operation result.

`validUntil` is enforced against the DO's current time. Once it passes, access behaves as read-only even if customer-management cannot run reconciliation. This is intentionally independent of source history.

### 5. Keep access enforcement small and explicit

The beta supports two modes:

- `read_write`: existing authenticated reads and writes are allowed.
- `read_only`: pull, encrypted export, device listing, and security-reducing revocation remain allowed; sync mutations, envelope writes, pairing, device additions, and other access-increasing writes are rejected.

No capability-merging engine lives in the backend. The DO consumes the already evaluated `tier`, `mode`, `validUntil`, and `version`.

### 6. Preserve the Phase 2 wire contract

The RPC surface is callable only through the Cloudflare binding; it does not add public `/v1/*` fields or bearer authentication. Existing device signatures, payload schemas, status semantics, BYO behavior, and the single-vault development routing remain unchanged unless a managed effective state is present on that object.

## Risks / Trade-offs

- [D1 commits but initialization times out] → Retry with the same onboarding-session operation ID; the DO returns the persisted result.
- [The response succeeds but customer-management misses it] → The identical retry is side-effect free and returns the same identifiers and version.
- [An operation ID is accidentally reused] → Compare canonical immutable-input hashes and return a conflict instead of guessing.
- [Entitlement updates arrive out of order] → Ignore lower versions and reject unequal equal-version payloads.
- [Control-plane reconciliation is unavailable at expiry] → Enforce `validUntil` locally and fall back to read-only.
- [Read-only blocks a security escape hatch] → Centralize the operation policy and explicitly allow reads, export, listing, and revocation tests.

## Migration Plan

1. Add Durable Object SQLite schema migration(s) for managed initialization, control operations, and effective entitlement state.
2. Add RPC types and methods to the existing exported class.
3. Route existing data-plane operations through the local effective-access guard while preserving pre-managed behavior.
4. Deploy the backend before deploying customer-management with the external binding.
5. Verify idempotency, version ordering, expiry, read-only policy, and unchanged Phase 2 contract in staging.

Rollback disables customer-management onboarding first. The backend schema and RPC methods can remain dormant; active vault data and issued Durable Object handles must not be removed or reused.

## Open Questions

None for the beta scope. Commercial entitlement policy and new passkey-login behavior belong to later changes.
