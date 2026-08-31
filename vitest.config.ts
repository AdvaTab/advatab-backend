import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: {
      bindings: {
        SETUP_TOKEN: 'test-setup-token-with-high-entropy-00000001',
        RECOVERY_TOKEN: 'test-recovery-token-with-high-entropy-00000002',
      },
    },
  })],
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/load.test.ts'],
    testTimeout: 75_000,
  },
});
