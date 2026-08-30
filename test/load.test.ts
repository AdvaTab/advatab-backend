import { exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import { createDevice, jsonRequest, responseJson, signedRequest } from './helpers';

interface SyncPage {
  serverRevision: number;
  nextCursor: number;
  hasMore: boolean;
  changes: Array<{ itemId: string }>;
}

it('stores 10,000 opaque items in 500-item batches and bootstraps in pages', async () => {
  const device = await createDevice('load-device');
  const bootstrap = await exports.default.fetch(jsonRequest('/v1/bootstrap/device', 'POST', {
    protocolVersion: 1,
    vaultId: 'load-vault',
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
  }, { authorization: 'Bearer load-test-setup-token-with-high-entropy-0001' }));
  const { vaultHandle } = await responseJson<{ vaultHandle: string }>(bootstrap);

  let cursor = 0;
  for (let batch = 0; batch < 20; batch++) {
    const mutations = Array.from({ length: 500 }, (_, offset) => ({
      itemId: `item-${String(batch * 500 + offset).padStart(5, '0')}`,
      expectedRevision: 0,
      deleted: false,
      cryptoVersion: 1,
      nonce: 'AA==',
      ciphertext: 'AQ==',
    }));
    const request = await signedRequest('/v1/sync', 'POST', device, vaultHandle, {
      protocolVersion: 1,
      syncRequestId: `load-batch-${String(batch).padStart(2, '0')}`,
      cursor,
      mutations,
      limit: 500,
    });
    const page = await responseJson<SyncPage>(await exports.default.fetch(request));
    expect(page.changes).toHaveLength(500);
    cursor = page.nextCursor;
  }
  expect(cursor).toBe(10_000);

  let bootstrapCursor = 0;
  let received = 0;
  let pageNumber = 0;
  do {
    const request = await signedRequest('/v1/sync', 'POST', device, vaultHandle, {
      protocolVersion: 1,
      syncRequestId: `bootstrap-page-${String(pageNumber).padStart(2, '0')}`,
      cursor: bootstrapCursor,
      mutations: [],
      limit: 1000,
    });
    const page = await responseJson<SyncPage>(await exports.default.fetch(request));
    received += page.changes.length;
    bootstrapCursor = page.nextCursor;
    pageNumber += 1;
    if (!page.hasMore) break;
  } while (pageNumber < 20);

  expect(received).toBe(10_000);
  expect(bootstrapCursor).toBe(10_000);
  expect(pageNumber).toBe(10);
});
