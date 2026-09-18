import { env } from 'cloudflare:workers';
import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { expect, it } from 'vitest';
import type {
  InitializeManagedVaultRequest,
  ManagedVaultControlRpc,
  SetEffectiveEntitlementRequest,
} from '../src/managed-control';
import { canonicalJson, effectiveAccessMode, immutableInputHash } from '../src/managed-control';
import { createDevice, jsonRequest, responseJson, signedRequest } from './helpers';

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

it('fails closed to read-only when finite effective validity has passed', () => {
  const now = Date.parse('2030-01-01T00:00:00.000Z');
  expect(effectiveAccessMode('read_write', '2029-12-31T23:59:59.999Z', now)).toBe('read_only');
  expect(effectiveAccessMode('read_write', '2030-01-01T00:00:00.001Z', now)).toBe('read_write');
  expect(effectiveAccessMode('read_write', null, now)).toBe('read_write');
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

it('stores finite validity and accepts an indefinite replacement while rejecting non-RFC3339 timestamps', async () => {
  const device = await createDevice(`managed-validity-device-${crypto.randomUUID()}`);
  const { stub } = controlStub();
  await stub.initializeManagedVault({
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-validity', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  });
  expect(await stub.setEffectiveEntitlement({
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_write',
    validUntil: '2030-01-01T00:00:00.000Z', version: 2,
  })).toEqual({ applied: true, entitlementVersion: 2 });
  expect(await stub.setEffectiveEntitlement({
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 3,
  })).toEqual({ applied: true, entitlementVersion: 3 });

  let invalidTimestampError: unknown;
  try {
    await stub.setEffectiveEntitlement({
      operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: 'tomorrow', version: 4,
    });
  } catch (error) {
    invalidTimestampError = error;
  }
  expect(invalidTimestampError).toMatchObject({ message: expect.stringMatching(/ISO timestamp/) });
});

it('keeps pull, envelope listing, device listing, and revocation available in read-only mode', async () => {
  const deviceA = await createDevice(`managed-read-only-a-${crypto.randomUUID()}`);
  const deviceB = await createDevice(`managed-read-only-b-${crypto.randomUUID()}`);
  const { raw, stub } = controlStub();
  const initialized = await stub.initializeManagedVault({
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-read-only', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: deviceA.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceA.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  });
  const pairing = await responseJson<{ pairingId: string; pollingSecret: string }>(await raw.fetch(jsonRequest('/v1/pairings', 'POST', {
    protocolVersion: 1,
    transferPublicKey: deviceB.publicKey,
    device: { deviceId: deviceB.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceB.publicKey },
  })));
  const approve = await signedRequest(`/v1/pairings/${pairing.pairingId}/approve`, 'POST', deviceA, initialized.vaultHandle, { transferPayload: 'd3JhcHBlZA==' });
  expect((await raw.fetch(approve)).status).toBe(200);
  await stub.setEffectiveEntitlement({
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_only', validUntil: null, version: 2,
  });

  const listedDevices = await raw.fetch(await signedRequest('/v1/devices', 'GET', deviceA, initialized.vaultHandle));
  expect(listedDevices.status).toBe(200);
  expect((await responseJson<{ devices: Array<{ deviceId: string }> }>(listedDevices)).devices.map((entry) => entry.deviceId)).toEqual([deviceA.deviceId, deviceB.deviceId]);
  const listedEnvelopes = await raw.fetch(await signedRequest('/v1/envelopes', 'GET', deviceA, initialized.vaultHandle));
  expect(listedEnvelopes.status).toBe(200);
  expect(await responseJson<{ envelopes: unknown[] }>(listedEnvelopes)).toEqual({ envelopes: [] });
  const revoke = await raw.fetch(await signedRequest(`/v1/devices/${deviceB.deviceId}`, 'DELETE', deviceA, initialized.vaultHandle));
  expect(revoke.status).toBe(204);

  const mutation = await raw.fetch(await signedRequest('/v1/sync', 'POST', deviceA, initialized.vaultHandle, {
    protocolVersion: 1, syncRequestId: crypto.randomUUID(), cursor: 0,
    mutations: [{ itemId: 'read-only-item', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AQ==' }],
  }));
  expect(mutation.status).toBe(403);
  expect(await responseJson<{ error: { code: string } }>(mutation)).toMatchObject({ error: { code: 'managed_read_only' } });
  const envelopeWrite = await raw.fetch(await signedRequest('/v1/envelopes/recovery', 'PUT', deviceA, initialized.vaultHandle, {
    type: 'recovery-v1', credentialRef: null, cryptoVersion: 1, nonce: null, ciphertext: 'ZW52ZWxvcGU=',
  }));
  expect(envelopeWrite.status).toBe(403);
  const envelopeDelete = await raw.fetch(await signedRequest('/v1/envelopes/recovery', 'DELETE', deviceA, initialized.vaultHandle));
  expect(envelopeDelete.status).toBe(403);
  const pairingCreate = await raw.fetch(jsonRequest('/v1/pairings', 'POST', {
    protocolVersion: 1, transferPublicKey: deviceB.publicKey,
    device: { deviceId: `blocked-${deviceB.deviceId}`, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceB.publicKey },
  }));
  expect(pairingCreate.status).toBe(201);
  const pendingPairings = await raw.fetch(await signedRequest('/v1/pairings/pending', 'GET', deviceA, initialized.vaultHandle));
  expect(pendingPairings.status).toBe(200);
  expect((await responseJson<{ pairings: Array<{ device: { deviceId: string } }> }>(pendingPairings)).pairings.map((entry) => entry.device.deviceId)).toContain(`blocked-${deviceB.deviceId}`);
  const pairingPoll = await raw.fetch(jsonRequest(`/v1/pairings/${pairing.pairingId}`, 'GET', undefined, { authorization: `AdvaTab-Pairing ${pairing.pollingSecret}` }));
  expect(pairingPoll.status).toBe(200);
  const pairingConsume = await raw.fetch(jsonRequest(`/v1/pairings/${pairing.pairingId}/consume`, 'POST', undefined, { authorization: `AdvaTab-Pairing ${pairing.pollingSecret}` }));
  expect(pairingConsume.status).toBe(204);
});

it('applies the read-write/read-only/expired operation matrix', async () => {
  const device = await createDevice(`managed-matrix-device-${crypto.randomUUID()}`);
  const { raw, stub } = controlStub();
  const initialized = await stub.initializeManagedVault({
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-matrix', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  });
  const readWriteMutation = await raw.fetch(await signedRequest('/v1/sync', 'POST', device, initialized.vaultHandle, {
    protocolVersion: 1, syncRequestId: crypto.randomUUID(), cursor: 0,
    mutations: [{ itemId: 'matrix-item', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AQ==' }],
  }));
  expect(readWriteMutation.status).toBe(200);

  await stub.setEffectiveEntitlement({
    operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_only', validUntil: null, version: 2,
  });
  const explicitReadOnly = await raw.fetch(await signedRequest('/v1/sync', 'POST', device, initialized.vaultHandle, {
    protocolVersion: 1, syncRequestId: crypto.randomUUID(), cursor: 1,
    mutations: [{ itemId: 'matrix-item-2', expectedRevision: 0, deleted: true }],
  }));
  expect(explicitReadOnly.status).toBe(403);

  const expiredDevice = await createDevice(`managed-expired-device-${crypto.randomUUID()}`);
  const expiredControl = controlStub();
  const expired = await expiredControl.stub.initializeManagedVault({
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-expired', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: expiredDevice.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: expiredDevice.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: '2000-01-01T00:00:00.000Z', version: 1 },
  });
  const expiredMutation = await expiredControl.raw.fetch(await signedRequest('/v1/sync', 'POST', expiredDevice, expired.vaultHandle, {
    protocolVersion: 1, syncRequestId: crypto.randomUUID(), cursor: 0,
    mutations: [{ itemId: 'expired-item', expectedRevision: 0, deleted: true }],
  }));
  expect(expiredMutation.status).toBe(403);
});
