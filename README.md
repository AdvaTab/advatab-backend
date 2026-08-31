# SupaTabs Sync Backend

Phase 2 sync backend for SupaTabs Sync Protocol v1. A deployment owns one
encrypted vault backed by one SQLite Durable Object. The service stores opaque
ciphertext and device public keys; it never receives tab data or account
encryption keys in plaintext. `customer-management` is the separate Phase 3
control plane that can provision managed deployments without changing this
wire contract.

## Requirements

- Node.js 22 or newer (Node.js 24 is used in CI)
- A Cloudflare account with Workers enabled
- Wrangler authentication (`npx wrangler login`) for manual deployment

## Local development

```bash
npm install
npm run cf:typegen
npm test
npm run dev
```

Create `.dev.vars` before the first local bootstrap:

```dotenv
SETUP_TOKEN=replace-with-output-from-npm-run-setup-token
# Optional until recovery enrollment is needed:
RECOVERY_TOKEN=replace-with-a-separate-recovery-enrollment-token
```

Generate a high-entropy token with `npm run setup-token`. Local Durable Object data is persisted under `.wrangler/state`.

Useful checks:

```bash
npm run typecheck
npm run build
npm run test:load
SUPATABS_URL=http://127.0.0.1:8787 SUPATABS_SETUP_TOKEN=... npm run smoke
```

The load test is intentionally separate from the normal test command. It writes 10,000 opaque records in 500-item batches and verifies a ten-page bootstrap.

## Bootstrap

1. Install the setup secret for the target environment:

   ```bash
   npx wrangler secret put SETUP_TOKEN --env staging
   ```

2. Deploy with `npm run deploy:staging`.
3. Generate the first device’s ECDSA P-256 keypair in the extension and call `POST /v1/bootstrap/device` with `Authorization: Bearer <SETUP_TOKEN>`.
4. Persist the returned `vaultHandle` with the device credentials.
5. Remove the Cloudflare secret after successful bootstrap:

   ```bash
   npx wrangler secret delete SETUP_TOKEN --env staging
   ```

The Durable Object persists that bootstrap has completed, so restoring the same
secret cannot initialize a different vault or device. A retry for the exact
same vault/device/key is allowed only to recover a lost bootstrap response. A
lost final device cannot be replaced through bootstrap; use another paired
device, recovery enrollment, or Cloudflare point-in-time recovery.

If a recovery secret is used without a trusted device, configure a separate
`RECOVERY_TOKEN` and call `POST /v1/recovery/device` with the existing
`vaultId`. The extension sends only the new device public key; it downloads
the opaque recovery envelope and unwraps the AccountKey locally. Recovery
enrollment does not alter the one-time bootstrap marker.

For a deployed environment, install the recovery-enrollment token separately:

```bash
npx wrangler secret put RECOVERY_TOKEN --env staging
```

## Deployment

`wrangler.jsonc` defines isolated `staging` and `production` Workers. Each environment receives a separate SQLite Durable Object namespace while using the same exported class definition.

Manual commands:

```bash
npm run deploy:staging
npm run deploy:production
```

The manual GitHub deployment workflow requires protected GitHub Environments named `staging` and `production`, each configured with:

- secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`;
- variable `SUPATABS_URL` containing the deployed Worker URL;
- optional secret `SUPATABS_SETUP_TOKEN`, used only when smoke-testing a fresh deployment.

The Cloudflare API token should be scoped to Workers Scripts edit access for the target account. Production is never deployed on push; it requires manual workflow dispatch and can be protected with GitHub reviewers.

## Operations

- Inspect structured request logs with `npx wrangler tail --env staging` or the Workers dashboard.
- Deploy a known Git revision to roll application code back. Durable Object schema changes are forward-only and should be introduced as ordered migrations.
- Use Cloudflare Durable Object point-in-time recovery for storage-level recovery. The protocol intentionally has no plaintext server-side backup format.
- Remove `.wrangler/state` only when intentionally resetting local development data. Never commit `.dev.vars` or setup/device secrets.

## Protocol layout

- `src/index.ts`: CORS, request limits, single-vault routing, safe request logging.
- `src/vault.ts`: Durable Object routes, SQLite transactions, devices, envelopes, pairing, and sync persistence.
- `src/sync-engine.ts`: portable CAS decisions, cursor rules, and response-size pagination.
- `src/signatures.ts`: the documented RFC 9421 SupaTabs signature profile and a reusable WebCrypto signer.
- `src/validation.ts` and `src/protocol.ts`: dependency-free wire validation and public TypeScript contracts.
- `spec/phase2-wire-fixtures.md`: canonical cross-repository request, response, encoding, and signature fixtures.

The normative protocol is in `spec/01-sync-backend-spec.md`.
