import { env } from 'cloudflare:workers';
import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { expect, it } from 'vitest';
import type {
  InitializeManagedVaultRequest,
  ManagedVaultControlRpc,
  SetEffectiveEntitlementRequest,
} from '../src/managed-control';
import { canonicalJson, immutableInputHash } from '../src/managed-control';
import { createDevice } from './helpers';

function controlStub(): { id: DurableObjectId; raw: DurableObjectStub; stub: ManagedVaultControlRpc } {
  const id = env.VAULTS!.newUniqueId();
  const raw = env.VAULTS!.get(id);
  return { id, raw, stub: raw as unknown as ManagedVaultControlRpc };
}

it('persists managed initialization and returns the stored result after eviction', async () => {
  const device = await createDevice(`managed-device-${crypto.randomUUID()}`);
  const { id, raw, stub } = controlStub();
  const input: InitializeManagedVaultRequest = {
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-1', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  };

  const first = await stub.initializeManagedVault(input);
  expect(first).toEqual({ status: 'initialized', vaultHandle: id.toString(), entitlementVersion: 1 });

  const rows = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT * FROM managed_effective_entitlements').toArray());
  expect(rows).toHaveLength(1);
  expect(Object.keys(rows[0] as object).sort()).toEqual(['mode', 'product', 'tier', 'updated_at', 'valid_until', 'version']);
  expect(rows[0]).toMatchObject({ product: 'cloud-sync', tier: 'tester', mode: 'read_write', valid_until: null, version: 1 });

  await evictDurableObject(stub as unknown as DurableObjectStub);
  const retry = await (env.VAULTS!.get(id) as unknown as ManagedVaultControlRpc).initializeManagedVault(input);
  expect(retry).toEqual(first);
});

it('rejects changed operation inputs and reinitialization of a different vault', async () => {
  const device = await createDevice(`managed-conflict-device-${crypto.randomUUID()}`);
  const { stub } = controlStub();
  const input: InitializeManagedVaultRequest = {
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-conflict', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  };
  const first = await stub.initializeManagedVault(input);

  let changedInputError: unknown;
  try {
    await stub.initializeManagedVault({ ...input, credential: { ...input.credential, credentialId: 'changed' } });
  } catch (error) {
    changedInputError = error;
  }
  expect(changedInputError).toMatchObject({ message: expect.stringMatching(/different control inputs/) });
  let secondInitializationError: unknown;
  try {
    await stub.initializeManagedVault({ ...input, operationId: crypto.randomUUID(), vaultId: crypto.randomUUID() });
  } catch (error) {
    secondInitializationError = error;
  }
  expect(secondInitializationError).toMatchObject({ message: expect.stringMatching(/already been initialized/) });
  expect(await stub.initializeManagedVault(input)).toEqual(first);
});

it('serializes identical concurrent initialization calls and hashes finite canonical inputs', async () => {
  expect(canonicalJson({ z: 1, a: { y: true, b: 2 } })).toBe('{"a":{"b":2,"y":true},"z":1}');
  await expect(immutableInputHash({ invalid: Number.NaN })).rejects.toThrow(/finite numbers/);

  const device = await createDevice(`managed-concurrent-device-${crypto.randomUUID()}`);
  const { id, stub } = controlStub();
  const input: InitializeManagedVaultRequest = {
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-concurrent', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  };
  const results = await Promise.all([
    stub.initializeManagedVault(input),
    stub.initializeManagedVault(input),
    stub.initializeManagedVault(input),
  ]);
  expect(results).toEqual([
    { status: 'initialized', vaultHandle: id.toString(), entitlementVersion: 1 },
    { status: 'initialized', vaultHandle: id.toString(), entitlementVersion: 1 },
    { status: 'initialized', vaultHandle: id.toString(), entitlementVersion: 1 },
  ]);
});

it('applies monotonic effective-entitlement updates and rejects equal-version conflicts', async () => {
  const device = await createDevice(`managed-entitlement-device-${crypto.randomUUID()}`);
  const { stub } = controlStub();
  const initialization: InitializeManagedVaultRequest = {
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-entitlement', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  };
  await stub.initializeManagedVault(initialization);

  const newer: SetEffectiveEntitlementRequest = {
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'pro', mode: 'read_write', validUntil: null, version: 2,
  };
  expect(await stub.setEffectiveEntitlement(newer)).toEqual({ applied: true, entitlementVersion: 2 });
  expect(await stub.setEffectiveEntitlement({
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_only', validUntil: null, version: 1,
  })).toEqual({ applied: false, entitlementVersion: 2 });
  expect(await stub.setEffectiveEntitlement({ ...newer, operationId: crypto.randomUUID() })).toEqual({ applied: false, entitlementVersion: 2 });

  let equalVersionError: unknown;
  try {
    await stub.setEffectiveEntitlement({ ...newer, operationId: crypto.randomUUID(), mode: 'read_only' });
  } catch (error) {
    equalVersionError = error;
  }
  expect(equalVersionError).toMatchObject({ message: expect.stringMatching(/already associated/) });
  expect(await stub.setEffectiveEntitlement(newer)).toEqual({ applied: true, entitlementVersion: 2 });
});
