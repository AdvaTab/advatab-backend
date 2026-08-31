import { exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import { signRequest } from '../src/signatures';
import { assertPageProgress } from '../src/sync-engine';
import { createDevice, jsonRequest, responseJson, signedRequest } from './helpers';

async function bootstrap() {
  const device = await createDevice('semantics-device');
  const response = await exports.default.fetch(jsonRequest('/v1/bootstrap/device', 'POST', {
    protocolVersion: 1,
    vaultId: 'semantics-vault',
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
  }, { authorization: 'Bearer test-setup-token-with-high-entropy-00000001' }));
  const { vaultHandle } = await responseJson<{ vaultHandle: string }>(response);
  return { device, vaultHandle };
}

it('handles mixed conflicts, monotonic revisions, pagination, and signature failures', async () => {
  const { device, vaultHandle } = await bootstrap();
  const seedBody = {
    protocolVersion: 1,
    syncRequestId: 'semantics-seed',
    cursor: 0,
    mutations: [{ itemId: 'item-one', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AQ==' }],
  };
  const seed = await signedRequest('/v1/sync', 'POST', device, vaultHandle, seedBody);

  const tampered = new Request(seed.url, {
    method: seed.method,
    headers: seed.headers,
    body: JSON.stringify({ ...seedBody, cursor: 1 }),
  });
  const tamperedResponse = await exports.default.fetch(tampered);
  expect(tamperedResponse.status).toBe(401);
  expect(await responseJson<{ error: { code: string } }>(tamperedResponse)).toMatchObject({ error: { code: 'unauthorized' } });

  const seedResult = await responseJson<{ serverRevision: number }>(await exports.default.fetch(seed));
  expect(seedResult.serverRevision).toBe(1);

  const mixed = await signedRequest('/v1/sync', 'POST', device, vaultHandle, {
    protocolVersion: 1,
    syncRequestId: 'semantics-mixed',
    cursor: 1,
    mutations: [
      { itemId: 'item-one', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'Ag==' },
      { itemId: 'item-two', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'Aw==' },
    ],
  });
  const mixedResult = await responseJson<{
    serverRevision: number;
    mutationResults: Array<{ status: string; revision?: number; current?: { revision: number } }>;
  }>(await exports.default.fetch(mixed));
  expect(mixedResult.serverRevision).toBe(2);
  expect(mixedResult.mutationResults[0]).toMatchObject({ status: 'conflict', current: { revision: 1 } });
  expect(mixedResult.mutationResults[1]).toMatchObject({ status: 'ok', revision: 2 });

  const firstPage = await signedRequest('/v1/sync', 'POST', device, vaultHandle, {
    protocolVersion: 1, syncRequestId: 'semantics-page-1', cursor: 0, mutations: [], limit: 1,
  });
  const pageOne = await responseJson<{ nextCursor: number; hasMore: boolean; changes: Array<{ itemId: string }> }>(await exports.default.fetch(firstPage));
  expect(pageOne).toMatchObject({ nextCursor: 1, hasMore: true, changes: [{ itemId: 'item-one' }] });

  const secondPage = await signedRequest('/v1/sync', 'POST', device, vaultHandle, {
    protocolVersion: 1, syncRequestId: 'semantics-page-2', cursor: pageOne.nextCursor, mutations: [], limit: 1,
  });
  const pageTwo = await responseJson<{ nextCursor: number; hasMore: boolean; changes: Array<{ itemId: string }> }>(await exports.default.fetch(secondPage));
  expect(pageTwo).toMatchObject({ nextCursor: 2, hasMore: false, changes: [{ itemId: 'item-two' }] });

  const expiredUnsigned = jsonRequest('/v1/devices', 'GET');
  const expired = await signRequest(expiredUnsigned, device.privateKey, device.deviceId, vaultHandle, Math.floor(Date.now() / 1000) - 1000);
  const expiredResponse = await exports.default.fetch(expired);
  expect(expiredResponse.status).toBe(401);
  expect(await responseJson<{ error: { code: string } }>(expiredResponse)).toMatchObject({ error: { code: 'signature_expired' } });
});

it('rejects a response that cannot advance a non-empty page', () => {
  expect(() => assertPageProgress(4, 4, true)).toThrow(/maxResponseBytes/);
  expect(() => assertPageProgress(4, 4, false)).not.toThrow();
});
