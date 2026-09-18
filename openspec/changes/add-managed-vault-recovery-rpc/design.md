## Context

The backend-owned `VaultDurableObject` already stores the managed vault identity, verified registration credential, DeviceAuth public identities, encrypted recovery envelope, effective entitlement, and idempotent control-operation results. Public Phase 2 pairing can transfer AccountKey from an existing device, while the custom-server recovery route relies on a deployment-wide operator token and therefore cannot authorize a specific managed customer.

Customer-management will own passkey challenges, recovery verifiers, access sessions, and business identities. It needs internal RPCs that verify the Durable Object's authoritative credential and restore a device after customer-management has authenticated a recovery credential. This change is coordinated with customer-management `add-managed-cloud-auth-recovery` and smart-tabs `add-managed-cloud-returning-user`.

## Goals / Non-Goals

**Goals:**

- Verify discoverable passkey assertions against the credential stored in the routed Durable Object.
- Register exactly one recovered DeviceAuth identity and return the matching encrypted recovery envelope idempotently.
- Support versioned recovery envelopes so explicit code replacement has no availability gap.
- Allow owner-authorized pairing and recovery in read-only mode while continuing to block data mutations.
- Preserve current public wire formats and all existing initialization/entitlement behavior.

**Non-Goals:**

- Storing Customer, email, invite, entitlement history, recovery verifier, or access-session state.
- Receiving a recovery root, recovery authorization value, envelope-decryption key, AccountKey, or private key.
- Authenticating customer-management callers over public HTTP; these methods remain typed binding RPCs.
- Adding PRF or deriving AccountKey from a passkey.

## Decisions

### Verify assertions where the credential is authoritative

Add:

```text
verifyManagedPasskey({
  operationId,
  challenge,
  rpId,
  expectedOrigin,
  assertion
}) -> {
  status: "verified",
  vaultHandle,
  protocolVersion,
  effectiveEntitlement
}
```

The assertion uses WebAuthn JSON/base64url encoding. The RPC requires an initialized managed vault, verifies the assertion credential ID against the stored credential, requires `webauthn.get`, user presence and verification, validates the RP ID/origin/challenge, and requires `response.userHandle` to equal the Durable Object's 32-byte handle. It applies WebAuthn signature-counter rules and stores the new counter and idempotent operation result before returning.

An identical retry returns its stored result before reapplying counter checks. A new operation using a replayed challenge remains the control plane's responsibility to reject; the RPC still rejects invalid signatures and counter regressions.

### Recover one public device and one encrypted envelope atomically

Add:

```text
recoverManagedDevice({
  operationId,
  recoveryGeneration,
  device
}) -> {
  status: "recovered",
  vaultId,
  vaultHandle,
  deviceId,
  recoveryEnvelope,
  protocolVersion,
  effectiveEntitlement
}
```

Customer-management authorizes the recovery generation before invoking this RPC. The object verifies that it is initialized and managed, finds that exact encrypted generation, validates the DeviceAuth P-256 public key, and transactionally inserts the device plus operation result. An existing identical device is an idempotent success; the same device ID with another key conflicts. The response stores ciphertext in the Durable Object's operation result for deterministic retry but exposes no plaintext.

### Keep versioned encrypted recovery generations locally

Generation `1` is populated when the first signed `PUT /v1/envelopes/recovery-v1` succeeds for a managed vault. Add `storeManagedRecoveryGeneration({ operationId, generation, recoveryEnvelope })` for customer-management's explicit replacement saga and `hasManagedRecoveryGeneration({ generation })` for initial activation checks. Generations are positive, immutable once stored, and an identical retry succeeds. A generation with different ciphertext conflicts.

Old encrypted generations may remain stored after D1 revokes their verifier; they are unreachable through recovery because customer-management no longer authorizes that generation. Cleanup can remove revoked generations in a later operation but is not required for correctness.

### Extend the common control-operation ledger

Add all new method names to `managed_control_operations`. Canonical immutable-input hashes cover every security-relevant field, including assertion bytes, expected ceremony context, recovery generation, device public identity, and encrypted-envelope content. State and result are committed before return.

### Permit access restoration in read-only mode

For managed vaults, read-only mode continues to block sync mutations and ordinary envelope writes. It now permits the existing pairing lifecycle and the internal recovery/passkey RPCs. A newly paired or recovered device has no write exemption: subsequent requests use the same vault-wide read-only policy. Custom-server behavior is unchanged because it has no managed entitlement state.

This exception is preferable to denying encrypted export after subscription or tester access expires. Pairing still requires approval from an authenticated device, and recovery still requires customer-management authorization.

## Risks / Trade-offs

- [Customer-management incorrectly authorizes a recovery generation] → Keep the RPC private, scope it to one routed object, log only opaque operation IDs, and require exact generation/envelope existence.
- [Assertion verification diverges from registration] → Use the same maintained WebAuthn verification library and shared fixture corpus for RP/origin/user-handle/counter cases.
- [Concurrent passkey assertions race counters] → Serialize counter verification/update in Durable Object storage and preserve zero-counter multi-device credential behavior.
- [Read-only pairing increases the authorized-device set] → Require the unchanged cryptographic pairing approval and keep all resulting data writes blocked.
- [Encrypted control-operation results grow] → Store only the single compact recovery envelope and enforce existing request/result size limits.
- [Old encrypted generations consume storage] → Retain them for correctness initially and add safe cleanup only after customer-management revocation is durable.

## Migration Plan

1. Add schema/tables and RPC types without changing current public routes.
2. Deploy backend before customer-management begins invoking the methods.
3. Backfill generation `1` lazily from the existing managed `recovery-v1` envelope when first checked.
4. Enable read-only pairing only after tests prove mutations remain blocked.
5. Rollback stops callers from using new RPCs; stored credentials, devices, envelopes, and operation records remain compatible with existing sync.

## Open Questions

None.
