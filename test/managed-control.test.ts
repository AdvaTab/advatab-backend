import { env } from 'cloudflare:workers';
import { evictDurableObject } from 'cloudflare:test';
import { expect, it } from 'vitest';
import type {
  InitializeManagedVaultRequest,
  ManagedVaultControlRpc,
} from '../src/managed-control';
import { createDevice } from './helpers';

function controlStub(): { id: DurableObjectId; stub: ManagedVaultControlRpc } {
  const id = env.VAULTS!.newUniqueId();
  return { id, stub: env.VAULTS!.get(id) as unknown as ManagedVaultControlRpc };
}

it('persists managed initialization and returns the stored result after eviction', async () => {
  const device = await createDevice(`managed-device-${crypto.randomUUID()}`);
  const { id, stub } = controlStub();
  const input: InitializeManagedVaultRequest = {
    operationId: crypto.randomUUID(),
    vaultId: crypto.randomUUID(),
    credential: { credentialId: 'credential-1', publicKey: 'cHVibGljLWtleQ', signCount: 0 },
    device: { deviceId: device.deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: device.publicKey },
    effectiveEntitlement: { product: 'cloud-sync', tier: 'tester', mode: 'read_write', validUntil: null, version: 1 },
  };

  const first = await stub.initializeManagedVault(input);
  expect(first).toEqual({ status: 'initialized', vaultHandle: id.toString(), entitlementVersion: 1 });

  await evictDurableObject(stub as unknown as DurableObjectStub);
  const retry = await (env.VAULTS!.get(id) as unknown as ManagedVaultControlRpc).initializeManagedVault(input);
  expect(retry).toEqual(first);
});
