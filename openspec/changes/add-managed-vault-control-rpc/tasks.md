## 1. Durable Object persistence

- [x] 1.1 Add a Durable Object SQLite migration for managed initialization metadata, effective entitlements, and control-operation results.
- [x] 1.2 Add canonical immutable-input hashing and conflict-safe operation-result lookup shared by both RPC methods.
- [x] 1.3 Define and export typed request/result models for `initializeManagedVault` and `setEffectiveEntitlement`.

## 2. Managed initialization RPC

- [x] 2.1 Implement `initializeManagedVault` on the existing `VaultDurableObject` without adding a second DO class.
- [x] 2.2 Atomically persist the vault identity, first verified credential, first DeviceAuth public key, initial effective entitlement, and stored RPC result.
- [x] 2.3 Return the object’s own `ctx.id` handle and reject reinitialization with different permanent identity inputs.
- [x] 2.4 Add identical-retry, lost-response, concurrent-call, and changed-input conflict tests.

## 3. Effective entitlement RPC

- [x] 3.1 Implement `setEffectiveEntitlement` with higher-version apply, lower-version ignore, and equal-version identical-payload rules.
- [x] 3.2 Persist only product, tier, mode, validity, and version; verify no invite, billing, or entitlement-history fields enter the DO.
- [ ] 3.3 Add tests for out-of-order updates, equal-version conflicts, indefinite validity, and local finite expiry.

## 4. Data-plane enforcement

- [ ] 4.1 Centralize effective access evaluation so expired finite grants behave as `read_only` without D1.
- [ ] 4.2 Permit pull, encrypted export, device listing, and security-reducing revocation in `read_only` mode.
- [ ] 4.3 Reject sync mutations, envelope writes, pairing, device additions, and other access-increasing operations atomically in `read_only` mode.
- [ ] 4.4 Add operation-matrix tests for `read_write`, explicit `read_only`, and locally expired states.

## 5. Compatibility and deployment

- [ ] 5.1 Add a typed external-namespace contract fixture consumable by customer-management.
- [ ] 5.2 Run regression tests proving every existing Phase 2 endpoint, signature profile, payload, and BYO behavior is unchanged.
- [ ] 5.3 Document backend-first deployment, the backend-owned namespace/migration boundary, observability, and rollback procedure.
- [ ] 5.4 Run backend tests and strict OpenSpec validation before customer-management staging integration.
