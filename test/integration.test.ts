import { env, exports } from 'cloudflare:workers';
import { evictDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { createDevice, jsonRequest, responseJson, signedRequest } from './helpers';

interface ErrorBody { error: { code: string } }

describe('SupaTabs sync backend', () => {
  it('runs the complete two-device lifecycle and survives eviction', async () => {
    const before = await exports.default.fetch('https://sync.test/v1/info');
    expect(before.status).toBe(200);
    expect(await responseJson<{ setupRequired: boolean }>(before)).toMatchObject({ setupRequired: true });

    const deviceA = await createDevice('device-a');
    const bootstrapRequest = jsonRequest('/v1/bootstrap/device', 'POST', {
      protocolVersion: 1,
      vaultId: 'vault-test',
      device: { deviceId: deviceA.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceA.publicKey },
    }, { authorization: 'Bearer test-setup-token-with-high-entropy-00000001' });
    const bootstrap = await exports.default.fetch(bootstrapRequest.clone() as unknown as RequestInfo);
    expect(bootstrap.status).toBe(201);
    const { vaultHandle } = await responseJson<{ vaultHandle: string }>(bootstrap);

    const repeatedBootstrap = await exports.default.fetch(bootstrapRequest.clone() as unknown as RequestInfo);
    expect(repeatedBootstrap.status).toBe(200);
    expect(await responseJson<{ vaultHandle: string; vaultId: string; deviceId: string }>(repeatedBootstrap)).toMatchObject({
      vaultHandle,
      vaultId: 'vault-test',
      deviceId: deviceA.deviceId,
    });

    const differentDevice = await createDevice('different-device');
    const differentBootstrap = jsonRequest('/v1/bootstrap/device', 'POST', {
      protocolVersion: 1,
      vaultId: 'vault-test',
      device: { deviceId: differentDevice.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: differentDevice.publicKey },
    }, { authorization: 'Bearer test-setup-token-with-high-entropy-00000001' });
    const differentResponse = await exports.default.fetch(differentBootstrap);
    expect(differentResponse.status).toBe(409);
    expect(await responseJson<ErrorBody>(differentResponse)).toMatchObject({ error: { code: 'setup_already_completed' } });

    const firstSyncBody = {
      protocolVersion: 1,
      syncRequestId: 'sync-request-1',
      cursor: 0,
      mutations: [{ itemId: 'item-a', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVydGV4dA==' }],
      limit: 500,
    };
    const firstSync = await signedRequest('/v1/sync', 'POST', deviceA, vaultHandle, firstSyncBody);
    const firstResponse = await exports.default.fetch(firstSync.clone() as unknown as RequestInfo);
    expect(firstResponse.status).toBe(200);
    const firstText = await firstResponse.text();
    expect(JSON.parse(firstText)).toMatchObject({ serverRevision: 1, nextCursor: 1, mutationResults: [{ status: 'ok', revision: 1 }] });

    const retryResponse = await exports.default.fetch(firstSync.clone() as unknown as RequestInfo);
    expect(await retryResponse.text()).toBe(firstText);

    const reused = await signedRequest('/v1/sync', 'POST', deviceA, vaultHandle, { ...firstSyncBody, cursor: 1 });
    const reusedResponse = await exports.default.fetch(reused);
    expect(reusedResponse.status).toBe(409);
    expect(await responseJson<ErrorBody>(reusedResponse)).toMatchObject({ error: { code: 'request_id_reused' } });

    const deletion = await signedRequest('/v1/sync', 'POST', deviceA, vaultHandle, {
      protocolVersion: 1, syncRequestId: 'sync-request-delete', cursor: 1,
      mutations: [{ itemId: 'item-a', expectedRevision: 1, deleted: true }],
    });
    expect((await responseJson<{ serverRevision: number }>(await exports.default.fetch(deletion))).serverRevision).toBe(2);

    const restoration = await signedRequest('/v1/sync', 'POST', deviceA, vaultHandle, {
      protocolVersion: 1, syncRequestId: 'sync-request-restore', cursor: 2,
      mutations: [{ itemId: 'item-a', expectedRevision: 2, deleted: false, cryptoVersion: 1, nonce: 'bm9uY2U=', ciphertext: 'cmVzdG9yZQ==' }],
    });
    const restore = await responseJson<{ mutationResults: Array<{ status: string; code: string }> }>(await exports.default.fetch(restoration));
    expect(restore.mutationResults[0]).toMatchObject({ status: 'conflict', code: 'tombstone_terminal' });

    const deviceB = await createDevice('device-b');
    const pairingCreate = jsonRequest('/v1/pairings', 'POST', {
      protocolVersion: 1,
      transferPublicKey: deviceB.publicKey,
      device: { deviceId: deviceB.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceB.publicKey },
    });
    const pairing = await responseJson<{ pairingId: string; pollingSecret: string }>(await exports.default.fetch(pairingCreate));

    const pendingRequest = await signedRequest('/v1/pairings/pending', 'GET', deviceA, vaultHandle);
    const pending = await responseJson<{
      pairings: Array<{ pairingId: string; transferPublicKey: string; device: { deviceId: string; authAlgorithm: string; authPublicKey: string } }>;
    }>(await exports.default.fetch(pendingRequest));
    expect(pending.pairings.map((entry) => entry.pairingId)).toContain(pairing.pairingId);
    expect(pending.pairings.find((entry) => entry.pairingId === pairing.pairingId)).toMatchObject({
      transferPublicKey: deviceB.publicKey,
      device: { deviceId: deviceB.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: deviceB.publicKey },
    });

    const approveRequest = await signedRequest(`/v1/pairings/${pairing.pairingId}/approve`, 'POST', deviceA, vaultHandle, { transferPayload: 'd3JhcHBlZC1hY2NvdW50LWtleQ==' });
    const approveResponse = await exports.default.fetch(approveRequest);
    expect(approveResponse.status).toBe(200);
    await approveResponse.text();

    const poll = await exports.default.fetch(jsonRequest(`/v1/pairings/${pairing.pairingId}`, 'GET', undefined, { authorization: `SupaTabs-Pairing ${pairing.pollingSecret}` }));
    expect(await responseJson<{ state: string; vaultHandle: string }>(poll)).toMatchObject({ state: 'approved', vaultHandle });

    const consume = jsonRequest(`/v1/pairings/${pairing.pairingId}/consume`, 'POST', undefined, { authorization: `SupaTabs-Pairing ${pairing.pollingSecret}` });
    expect((await exports.default.fetch(consume.clone() as unknown as RequestInfo)).status).toBe(204);
    expect((await exports.default.fetch(consume.clone() as unknown as RequestInfo)).status).toBe(204);

    const envelopePut = await signedRequest('/v1/envelopes/recovery-envelope', 'PUT', deviceB, vaultHandle, {
      type: 'recovery-v1', credentialRef: null, cryptoVersion: 1, nonce: 'bm9uY2U=', ciphertext: 'ZW52ZWxvcGU=',
    });
    const envelopeResponse = await exports.default.fetch(envelopePut);
    expect(envelopeResponse.status).toBe(200);
    await envelopeResponse.text();
    const envelopesRequest = await signedRequest('/v1/envelopes', 'GET', deviceB, vaultHandle);
    const envelopes = await responseJson<{ envelopes: Array<{ envelopeId: string }> }>(await exports.default.fetch(envelopesRequest));
    expect(envelopes.envelopes).toHaveLength(1);

    const objectId = env.VAULTS!.idFromName('default');
    await evictDurableObject(env.VAULTS!.get(objectId));
    const afterEviction = await signedRequest('/v1/devices', 'GET', deviceB, vaultHandle);
    const devices = await responseJson<{ devices: Array<{ deviceId: string }> }>(await exports.default.fetch(afterEviction));
    expect(devices.devices.map((entry) => entry.deviceId)).toEqual(['device-a', 'device-b']);

    const revoke = await signedRequest('/v1/devices/device-a', 'DELETE', deviceB, vaultHandle);
    expect((await exports.default.fetch(revoke)).status).toBe(204);
    const revokedRequest = await signedRequest('/v1/devices', 'GET', deviceA, vaultHandle);
    const revokedResponse = await exports.default.fetch(revokedRequest);
    expect(revokedResponse.status).toBe(401);
    expect(await responseJson<ErrorBody>(revokedResponse)).toMatchObject({ error: { code: 'device_revoked' } });
    const revokeLast = await signedRequest('/v1/devices/device-b', 'DELETE', deviceB, vaultHandle);
    const lastResponse = await exports.default.fetch(revokeLast);
    expect(lastResponse.status).toBe(409);
    expect(await responseJson<ErrorBody>(lastResponse)).toMatchObject({ error: { code: 'last_active_device' } });

    const recoveryDevice = await createDevice('recovery-device');
    const enrollBody = {
      protocolVersion: 1,
      vaultId: 'vault-test',
      device: { deviceId: recoveryDevice.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: recoveryDevice.publicKey, metadataCiphertext: null },
    };
    const enrollRequest = jsonRequest('/v1/recovery/device', 'POST', enrollBody, {
      authorization: 'Bearer test-recovery-token-with-high-entropy-00000002',
    });
    const enrolled = await exports.default.fetch(enrollRequest.clone() as unknown as RequestInfo);
    expect(enrolled.status).toBe(201);
    expect(await responseJson<{ vaultId: string; vaultHandle: string; deviceId: string }>(enrolled)).toMatchObject({
      vaultId: 'vault-test',
      vaultHandle,
      deviceId: recoveryDevice.deviceId,
    });

    const retry = await exports.default.fetch(enrollRequest.clone() as unknown as RequestInfo);
    expect(retry.status).toBe(200);

    const wrongToken = await exports.default.fetch(jsonRequest('/v1/recovery/device', 'POST', enrollBody, {
      authorization: 'Bearer wrong-recovery-token',
    }));
    expect(wrongToken.status).toBe(401);

    const signed = await signedRequest('/v1/devices', 'GET', recoveryDevice, vaultHandle);
    const deviceList = await responseJson<{ devices: Array<{ deviceId: string; authPublicKey: string }> }>(await exports.default.fetch(signed));
    expect(deviceList.devices.map((device) => device.deviceId)).toContain(recoveryDevice.deviceId);
    expect(deviceList.devices.find((device) => device.deviceId === recoveryDevice.deviceId)?.authPublicKey).toBe(recoveryDevice.publicKey);
  });

  it('rejects an arbitrary vault handle before authentication', async () => {
    const unknown = await createDevice('unknown-device');
    const signed = await signedRequest('/v1/devices', 'GET', unknown, 'not-a-real-handle');
    const response = await exports.default.fetch(signed);
    expect(response.status).toBe(404);
    expect(await responseJson<ErrorBody>(response)).toMatchObject({ error: { code: 'vault_not_found' } });
  });
});
