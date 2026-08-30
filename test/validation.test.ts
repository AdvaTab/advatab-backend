import { describe, expect, it } from 'vitest';
import { getLimits } from '../src/config';
import { ApiError } from '../src/errors';
import { parseSync } from '../src/validation';
import { decideMutation } from '../src/sync-engine';

const limits = getLimits({} as Env);

describe('protocol validation', () => {
  it('rejects duplicate item identifiers', () => {
    expect(() => parseSync({
      protocolVersion: 1,
      syncRequestId: 'request-id',
      cursor: 0,
      mutations: [
        { itemId: 'same-item', expectedRevision: 0, deleted: true },
        { itemId: 'same-item', expectedRevision: 0, deleted: true },
      ],
    }, limits)).toThrowError(ApiError);
  });

  it('rejects ciphertext larger than the configured decoded limit', () => {
    expect(() => parseSync({
      protocolVersion: 1,
      syncRequestId: 'request-id',
      cursor: 0,
      mutations: [{ itemId: 'large-item', expectedRevision: 0, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AAAA' }],
    }, { ...limits, maxItemBytes: 2 })).toThrowError(/exceeds maxItemBytes/);
  });

  it('treats tombstones as terminal but allows exact active CAS updates', () => {
    const active = { itemId: 'item', expectedRevision: 4, deleted: false, cryptoVersion: 1, nonce: 'AA==', ciphertext: 'AQ==' };
    expect(decideMutation({ revision: 4, deleted: false }, active)).toEqual({ apply: true });
    expect(decideMutation({ revision: 4, deleted: true }, active)).toEqual({ apply: false, code: 'tombstone_terminal' });
  });
});
