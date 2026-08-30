export interface Limits {
  maxRequestBytes: number;
  maxItemBytes: number;
  maxMutationsPerSync: number;
  maxResponseItems: number;
  maxResponseBytes: number;
  signatureWindowSeconds: number;
  pairingTtlSeconds: number;
  pairingRateLimit: number;
  pairingRateWindowSeconds: number;
}

const integer = (value: string | undefined, fallback: number): number => {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
};

export function getLimits(env: Env): Limits {
  return {
    maxRequestBytes: integer(env.MAX_REQUEST_BYTES, 10 * 1024 * 1024),
    maxItemBytes: integer(env.MAX_ITEM_BYTES, 1024 * 1024),
    maxMutationsPerSync: integer(env.MAX_MUTATIONS_PER_SYNC, 500),
    maxResponseItems: integer(env.MAX_RESPONSE_ITEMS, 1000),
    maxResponseBytes: integer(env.MAX_RESPONSE_BYTES, 1_500_000),
    signatureWindowSeconds: integer(env.SIGNATURE_WINDOW_SECONDS, 300),
    pairingTtlSeconds: integer(env.PAIRING_TTL_SECONDS, 600),
    pairingRateLimit: integer(env.PAIRING_RATE_LIMIT, 10),
    pairingRateWindowSeconds: integer(env.PAIRING_RATE_WINDOW_SECONDS, 600),
  };
}

export const defaultVaultName = (env: Env): string => env.DEFAULT_VAULT_NAME || 'default';
