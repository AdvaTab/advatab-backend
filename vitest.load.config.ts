import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: { bindings: { SETUP_TOKEN: 'load-test-setup-token-with-high-entropy-0001' } },
  })],
  test: { include: ['test/load.test.ts'], testTimeout: 120_000 },
});
