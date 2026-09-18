## 1. Control contracts and storage

- [ ] 1.1 Extend the exported managed control types with passkey verification, recovery-device enrollment, recovery-generation storage, and generation-availability RPC inputs/results.
- [ ] 1.2 Add Durable Object schema for immutable managed recovery-envelope generations and extend the control-operation method ledger for every new RPC.
- [ ] 1.3 Update the sibling contract fixture with canonical success, retry, conflict, and read-only examples consumed by customer-management.

## 2. Managed passkey authentication

- [ ] 2.1 Add WebAuthn assertion parsing and verification against the stored managed credential, including challenge, RP ID, origin, ceremony type, user presence, user verification, credential ID, signature, and 32-byte user-handle checks.
- [ ] 2.2 Implement `verifyManagedPasskey` with atomic signature-counter updates, effective-entitlement response data, and stored idempotent results.
- [ ] 2.3 Test valid discoverable credentials, wrong credential/vault/user handle, wrong challenge/RP/origin/type, missing verification, zero and monotonic counters, concurrency, replay under a new operation, and identical retry.

## 3. Recovery generations and device enrollment

- [ ] 3.1 Make the first successful managed `recovery-v1` envelope upload populate immutable recovery generation `1` without changing the public Phase 2 payload.
- [ ] 3.2 Implement idempotent generation availability and higher-generation storage RPCs with positive-generation validation and ciphertext conflict detection.
- [ ] 3.3 Implement `recoverManagedDevice` as one transaction that verifies the requested generation, validates or reuses the exact DeviceAuth identity, stores the control result, and returns the existing vault identity, encrypted envelope, protocol version, and effective entitlement.
- [ ] 3.4 Test missing envelopes, duplicate devices, conflicting device keys, concurrent enrollment, lost responses, mismatched operation reuse, multiple generations, and retained older ciphertext.

## 4. Read-only restoration policy

- [ ] 4.1 Permit managed passkey verification, the existing pairing lifecycle, generation checks/storage, and authorized recovery-device enrollment in read-only mode while keeping ordinary envelope and sync mutations blocked.
- [ ] 4.2 Test passkey, pairing, recovery, pull, encrypted export, listing, and revocation in read-only mode alongside rejection of every data- or entitlement-increasing mutation.
- [ ] 4.3 Confirm custom-server behavior remains unchanged when no managed entitlement state exists.

## 5. Security, compatibility, and validation

- [ ] 5.1 Add zero-knowledge and logging tests proving RPC inputs/results contain no recovery root, recovery authorization, AccountKey, private key, Customer metadata, or plaintext records.
- [ ] 5.2 Run existing Phase 2 endpoint, managed initialization, entitlement, migration, and size-limit suites to prove wire compatibility.
- [ ] 5.3 Run customer-management contract integration against the updated fixture and test backend-first deployment plus caller rollback.
- [ ] 5.4 Update backend documentation for new internal RPCs, read-only restoration exceptions, recovery-generation retention, observability, and rollback.
- [ ] 5.5 Run formatting, type checks, unit/integration tests, and strict OpenSpec validation for `add-managed-vault-recovery-rpc`.
