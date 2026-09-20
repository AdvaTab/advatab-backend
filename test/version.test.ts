import { describe, expect, it } from 'vitest';
import worker from '../src/index';

describe('version endpoint', () => {
  it('reports immutable build metadata without needing a vault handle', async () => {
    const response = await worker.fetch(new Request('https://sync.example/api/about/version'), {} as never);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    const metadata = await response.json() as Record<string, unknown>;
    expect(metadata).toMatchObject({
      component: 'backend',
      version: expect.stringMatching(/^\d+\.\d+\.\d+/),
      buildDate: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
    });
    expect(metadata.commit === null || /^[a-f0-9]{40}$/.test(String(metadata.commit))).toBe(true);
    expect([true, false, null]).toContain(metadata.dirty);
  });
});
