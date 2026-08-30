import { exports } from 'cloudflare:workers';
import { expect, it } from 'vitest';
import { createDevice, jsonRequest, responseJson } from './helpers';

it('persists and enforces the unauthenticated pairing creation limit', async () => {
  const owner = await createDevice('rate-owner');
  const bootstrap = await exports.default.fetch(jsonRequest('/v1/bootstrap/device', 'POST', {
    protocolVersion: 1,
    vaultId: 'rate-vault',
    device: { deviceId: owner.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: owner.publicKey },
  }, { authorization: 'Bearer test-setup-token-with-high-entropy-00000001' }));
  expect(bootstrap.status).toBe(201);
  await bootstrap.text();

  const proposed = await createDevice('rate-proposed');
  for (let index = 0; index < 10; index++) {
    const response = await exports.default.fetch(jsonRequest('/v1/pairings', 'POST', {
      protocolVersion: 1,
      transferPublicKey: proposed.publicKey,
      device: { deviceId: `rate-device-${index}`, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: proposed.publicKey },
    }));
    expect(response.status).toBe(201);
    await response.text();
  }
  const limited = await exports.default.fetch(jsonRequest('/v1/pairings', 'POST', {
    protocolVersion: 1,
    transferPublicKey: proposed.publicKey,
    device: { deviceId: 'rate-device-overflow', authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: proposed.publicKey },
  }));
  expect(limited.status).toBe(429);
  expect(await responseJson<{ error: { code: string } }>(limited)).toMatchObject({ error: { code: 'rate_limited' } });
});
