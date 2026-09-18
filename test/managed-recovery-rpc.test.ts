import { env, runInDurableObject } from 'cloudflare:test';
import { expect, it } from 'vitest';
import type { ManagedPasskeyAssertion, ManagedVaultControlRpc } from '../src/managed-control';
import { bytesToBase64, bytesToBase64Url, toArrayBuffer, utf8 } from '../src/encoding';
import { derToRaw } from '../src/managed-webauthn';
import { createDevice, signedRequest } from './helpers';

function cborCredentialKey(rawPublicKey: Uint8Array): string {
  const result = new Uint8Array(1 + 2 + 2 + 2 + 34 + 2 + 34);
  let offset = 0;
  result[offset++] = 0xa5;
  result.set([0x01, 0x02, 0x03, 0x26, 0x20, 0x01], offset); offset += 6;
  result.set([0x21, 0x58, 0x20], offset); offset += 3;
  result.set(rawPublicKey.subarray(1, 33), offset); offset += 32;
  result.set([0x22, 0x58, 0x20], offset); offset += 3;
  result.set(rawPublicKey.subarray(33, 65), offset);
  return bytesToBase64Url(result);
}

async function assertion(
  privateKey: CryptoKey,
  vaultHandle: string,
  credentialId: Uint8Array,
  challenge: string,
  counter: number,
  overrides: Partial<{ origin: string; rpId: string; userHandle: string; flags: number }> = {},
): Promise<ManagedPasskeyAssertion> {
  const origin = overrides.origin ?? 'https://cloud.test';
  const rpId = overrides.rpId ?? 'cloud.test';
  const userHandleBytes = overrides.userHandle ? Uint8Array.from(atob(overrides.userHandle), (entry) => entry.charCodeAt(0)) : Uint8Array.from(vaultHandle.match(/../g)!, (entry) => Number.parseInt(entry, 16));
  const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(utf8(rpId))));
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpHash);
  authenticatorData[32] = overrides.flags ?? 0x05;
  new DataView(authenticatorData.buffer, authenticatorData.byteOffset + 33, 4).setUint32(0, counter);
  const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(clientDataJSON)));
  const signed = new Uint8Array(authenticatorData.byteLength + clientHash.byteLength);
  signed.set(authenticatorData); signed.set(clientHash, authenticatorData.byteLength);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(signed)));
  return {
    id: bytesToBase64Url(credentialId),
    rawId: bytesToBase64Url(credentialId),
    type: 'public-key',
    response: {
      clientDataJSON: bytesToBase64Url(clientDataJSON),
      authenticatorData: bytesToBase64Url(authenticatorData),
      signature: bytesToBase64Url(signature),
      userHandle: bytesToBase64Url(userHandleBytes),
    },
  };
}

function controlStub(): { id: DurableObjectId; stub: ManagedVaultControlRpc; raw: DurableObjectStub } {
  const id = env.VAULTS!.newUniqueId();
  const raw = env.VAULTS!.get(id);
  return { id, raw, stub: raw as unknown as ManagedVaultControlRpc };
}

async function seedLegacyRecoveryEnvelopes(
  raw: DurableObjectStub,
  entries: Array<{ envelopeId: string; nonce: Uint8Array; ciphertext: Uint8Array; cryptoVersion?: number }>,
): Promise<void> {
  await runInDurableObject(raw, (_instance, state) => {
    for (const entry of entries) {
      const timestamp = new Date().toISOString();
      state.storage.sql.exec(
        `INSERT INTO key_envelopes(envelope_id, envelope_type, credential_ref, crypto_version, nonce, ciphertext, created_at, updated_at)
         VALUES (?, 'recovery-v1', NULL, ?, ?, ?, ?, ?)`,
        entry.envelopeId,
        entry.cryptoVersion ?? 1,
        toArrayBuffer(entry.nonce),
        toArrayBuffer(entry.ciphertext),
        timestamp,
        timestamp,
      );
    }
  });
}

it('rejects non-canonical 33-byte DER signature integers', () => {
  const r = Uint8Array.from([0x80, ...new Uint8Array(31).fill(0x11)]);
  const s = Uint8Array.from([0x80, ...new Uint8Array(31).fill(0x22)]);
  const signature = Uint8Array.from([0x30, 0x46, 0x02, 0x21, 0x00, ...r, 0x02, 0x21, 0x00, ...s]);

  expect(derToRaw(signature)).toHaveLength(64);
  const nonCanonical = signature.slice();
  nonCanonical[4] = 0x01;
  expect(() => derToRaw(nonCanonical)).toThrow('Invalid DER signature integer encoding.');
});

it('verifies managed discoverable assertions and persists the counter idempotently', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  const { id, raw, stub } = controlStub();
  const device = await createDevice(`passkey-device-${crypto.randomUUID()}`);
  await stub.initializeManagedVault({
    operationId: crypto.randomUUID(), vaultId: 'vault-passkey',
    credential: { credentialId: bytesToBase64Url(credentialId), publicKey: cborCredentialKey(rawPublic), signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'pro', mode: 'read_only', validUntil: null, version: 4 },
  });
  const challenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const input = {
    operationId: crypto.randomUUID(), challenge, rpId: 'cloud.test', expectedOrigin: 'https://cloud.test',
    assertion: await assertion(pair.privateKey, id.toString(), credentialId, challenge, 7),
  };
  const encodedCounter = Uint8Array.from(atob(input.assertion.response.authenticatorData.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - input.assertion.response.authenticatorData.length % 4) % 4)), (entry) => entry.charCodeAt(0));
  expect(Array.from(encodedCounter.slice(33, 37))).toEqual([0, 0, 0, 7]);
  const first = await stub.verifyManagedPasskey(input);
  expect(first.signCount).toBe(7);
  expect(first).toMatchObject({ status: 'verified', vaultHandle: id.toString(), protocolVersion: 1, effectiveEntitlement: { mode: 'read_only', version: 4 } });
  expect(await stub.verifyManagedPasskey(input)).toEqual(first);
  for (const invalid of [
    { ...input, operationId: crypto.randomUUID(), assertion: { ...input.assertion, id: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16))) } },
    { ...input, operationId: crypto.randomUUID(), challenge: bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32))), assertion: await assertion(pair.privateKey, id.toString(), credentialId, bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32))), 8) },
    { ...input, operationId: crypto.randomUUID(), expectedRpId: 'wrong.test', assertion: await assertion(pair.privateKey, id.toString(), credentialId, challenge, 8) },
    { ...input, operationId: crypto.randomUUID(), expectedOrigin: 'https://wrong.test', assertion: await assertion(pair.privateKey, id.toString(), credentialId, challenge, 8) },
    { ...input, operationId: crypto.randomUUID(), assertion: await assertion(pair.privateKey, id.toString(), credentialId, challenge, 8, { flags: 0x01 }) },
  ]) {
    let error: unknown;
    try { await stub.verifyManagedPasskey(invalid); } catch (caught) { error = caught; }
    expect(error).toBeDefined();
  }
  let counterError: unknown;
  try { await stub.verifyManagedPasskey({ ...input, operationId: crypto.randomUUID() }); } catch (caught) { counterError = caught; }
  const counterRow = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT credential_sign_count FROM managed_vault_meta').toArray());
  expect(counterRow[0]).toMatchObject({ credential_sign_count: 7 });
  expect(counterError).toMatchObject({ message: expect.stringMatching(/counter/) });
});

it('stores immutable generations and enrolls exactly one recovered device', async () => {
  const { stub, raw } = controlStub();
  const device = await createDevice(`recovery-device-${crypto.randomUUID()}`);
  const initialized = await stub.initializeManagedVault({
    operationId: crypto.randomUUID(), vaultId: 'vault-recovery',
    credential: { credentialId: 'credential-recovery', publicKey: 'not-used', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  });
  const envelope = { type: 'recovery-v1' as const, cryptoVersion: 1 as const, nonce: bytesToBase64(new Uint8Array(12).fill(3)), ciphertext: bytesToBase64(new Uint8Array([7, 8, 9])) };
  expect((await raw.fetch(await signedRequest('/v1/envelopes/recovery-v1', 'PUT', device, initialized.vaultHandle, envelope))).status).toBe(200);
  expect(await stub.confirmManagedRecoveryGeneration({ generation: 1 })).toEqual({ available: true, generation: 1 });
  await stub.setEffectiveEntitlement({ operationId: crypto.randomUUID(), product: 'cloud-sync', tier: 'tester', mode: 'read_only', validUntil: null, version: 2 });
  const envelope2 = { ...envelope, ciphertext: bytesToBase64(new Uint8Array([10, 11, 12])) };
  expect(await stub.storeManagedRecoveryGeneration({ operationId: crypto.randomUUID(), generation: 2, recoveryEnvelope: envelope2 })).toEqual({ stored: true, generation: 2 });
  const recoveredDevice = await createDevice(`recovered-device-${crypto.randomUUID()}`);
  const recoveryInput = { operationId: crypto.randomUUID(), recoveryGeneration: 2, device: { deviceId: recoveredDevice.deviceId, authAlgorithm: 'ecdsa-p256-sha256' as const, authPublicKey: recoveredDevice.publicKey } };
  let unavailable: unknown;
  try { await stub.recoverManagedDevice({ ...recoveryInput, operationId: crypto.randomUUID(), recoveryGeneration: 3 }); } catch (error) { unavailable = error; }
  expect(unavailable).toBeDefined();
  const recovered = await stub.recoverManagedDevice(recoveryInput);
  expect(recovered).toMatchObject({ status: 'recovered', vaultId: 'vault-recovery', vaultHandle: expect.any(String), deviceId: recoveredDevice.deviceId, recoveryEnvelope: envelope2, protocolVersion: 1 });
  expect(await stub.recoverManagedDevice(recoveryInput)).toEqual(recovered);
  expect(await Promise.all([stub.recoverManagedDevice(recoveryInput), stub.recoverManagedDevice(recoveryInput)])).toEqual([recovered, recovered]);
  const replacementKey = await createDevice(recoveredDevice.deviceId);
  let keyConflict: unknown;
  try { await stub.recoverManagedDevice({ ...recoveryInput, operationId: crypto.randomUUID(), device: { ...recoveryInput.device, authPublicKey: replacementKey.publicKey } }); } catch (error) { keyConflict = error; }
  expect(keyConflict).toMatchObject({ message: expect.stringMatching(/different key/) });
  let operationConflict: unknown;
  try { await stub.recoverManagedDevice({ ...recoveryInput, recoveryGeneration: 1 }); } catch (error) { operationConflict = error; }
  expect(operationConflict).toMatchObject({ message: expect.stringMatching(/different control inputs/) });
  let conflict: unknown;
  try { await stub.storeManagedRecoveryGeneration({ operationId: crypto.randomUUID(), generation: 2, recoveryEnvelope: { ...envelope2, ciphertext: bytesToBase64(new Uint8Array([10])) } }); } catch (error) { conflict = error; }
  expect(conflict).toMatchObject({ message: expect.stringMatching(/immutable|different envelope/) });
  const devices = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT device_id FROM devices').toArray());
  expect(devices).toHaveLength(2);
  const generations = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT generation FROM managed_recovery_generations ORDER BY generation').toArray());
  expect(generations).toEqual([{ generation: 1 }, { generation: 2 }]);
});

it('backfills an identical legacy recovery envelope before availability and storage', async () => {
  const { stub, raw } = controlStub();
  const device = await createDevice(`legacy-device-${crypto.randomUUID()}`);
  await stub.initializeManagedVault({
    operationId: crypto.randomUUID(), vaultId: 'vault-legacy',
    credential: { credentialId: 'credential-legacy', publicKey: 'not-used', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'pro', mode: 'read_write', validUntil: null, version: 1 },
  });
  const nonce = new Uint8Array([1, 2, 3]);
  const ciphertext = new Uint8Array([4, 5, 6]);
  await seedLegacyRecoveryEnvelopes(raw, [
    { envelopeId: 'legacy-recovery-a', nonce, ciphertext },
    { envelopeId: 'legacy-recovery-b', nonce, ciphertext },
  ]);

  const generationTwo = { type: 'recovery-v1' as const, cryptoVersion: 1 as const, nonce: bytesToBase64(new Uint8Array([7])), ciphertext: bytesToBase64(new Uint8Array([8, 9])) };
  expect(await stub.storeManagedRecoveryGeneration({ operationId: crypto.randomUUID(), generation: 2, recoveryEnvelope: generationTwo })).toEqual({ stored: true, generation: 2 });
  expect(await stub.hasManagedRecoveryGeneration({ generation: 1 })).toEqual({ available: true });
  const migrated = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT generation, recovery_envelope_json FROM managed_recovery_generations WHERE generation = 1').toArray());
  expect(migrated).toHaveLength(1);
  expect(migrated[0]).toMatchObject({ generation: 1 });
  expect(JSON.parse((migrated[0] as { recovery_envelope_json: string }).recovery_envelope_json)).toEqual({ type: 'recovery-v1', cryptoVersion: 1, nonce: bytesToBase64(nonce), ciphertext: bytesToBase64(ciphertext) });
  const generations = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT generation FROM managed_recovery_generations ORDER BY generation').toArray());
  expect(generations).toEqual([{ generation: 1 }, { generation: 2 }]);
});

it('fails closed when legacy recovery envelopes conflict', async () => {
  const { stub, raw } = controlStub();
  const device = await createDevice(`legacy-conflict-device-${crypto.randomUUID()}`);
  await stub.initializeManagedVault({
    operationId: crypto.randomUUID(), vaultId: 'vault-legacy-conflict',
    credential: { credentialId: 'credential-legacy-conflict', publicKey: 'not-used', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'pro', mode: 'read_write', validUntil: null, version: 1 },
  });
  await seedLegacyRecoveryEnvelopes(raw, [
    { envelopeId: 'legacy-conflict-a', nonce: new Uint8Array([1]), ciphertext: new Uint8Array([2]) },
    { envelopeId: 'legacy-conflict-b', nonce: new Uint8Array([3]), ciphertext: new Uint8Array([4]) },
  ]);

  expect(await stub.hasManagedRecoveryGeneration({ generation: 1 })).toEqual({ available: false });
  const stored: unknown[] = [];
  try {
    await stub.storeManagedRecoveryGeneration({
      operationId: crypto.randomUUID(), generation: 2,
      recoveryEnvelope: { type: 'recovery-v1', cryptoVersion: 1, nonce: 'BQ==', ciphertext: 'Bg==' },
    });
  } catch (error) { stored.push(error); }
  expect(stored[0]).toMatchObject({ message: expect.stringMatching(/conflicting envelope/) });
  const generations = await runInDurableObject(raw, (_instance, state) => state.storage.sql.exec('SELECT generation FROM managed_recovery_generations').toArray());
  expect(generations).toEqual([]);
});

it('keeps managed recovery RPC payloads opaque and free of control-plane secrets', () => {
  const publicControlPayload = JSON.stringify({
    operationId: 'operation-1', generation: 2,
    encryptedRecoveryEnvelope: { type: 'recovery-v1', cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AQ==' },
    device: { deviceId: 'device-1', authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: 'public-spki' },
  });
  expect(publicControlPayload).not.toMatch(/recoveryRoot|recoveryAuthorization|accountKey|privateKey|customer|plaintext/i);
  expect(publicControlPayload).toMatch(/ciphertext/);
});
