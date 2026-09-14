# Geboom Sync Backend

Phase 2 sync backend for AdvaTab Sync Protocol v1. A deployment owns one
encrypted vault backed by one SQLite Durable Object. The service stores opaque
ciphertext and device public keys; it never receives tab data or account
encryption keys in plaintext. `customer-management` is the separate Phase 3
control plane that can provision managed deployments without changing this
wire contract.

## Requirements

- Node.js 22 or newer (Node.js 24 is used in CI)
- A Cloudflare account with Workers enabled
- Wrangler authentication (`npx wrangler login`) for manual deployment

## Automated server installation

With Node.js 22 or newer and npm installed, run this from the backend checkout:

```bash
node scripts/install.mjs
```

The [installer](scripts/install.mjs) installs locked dependencies with `npm ci`,
opens Wrangler's browser login, then asks for your account's workers.dev name,
such as `klinki` or `klinki.workers.dev`. These are the only two interactive steps
on a successful run. An existing Cloudflare account with Workers access is required.
Custom domains such as `sync.example.com` are not supported by this installer.

It registers the subdomain if the account does not have one, deploys
`geboom-sync-production` and its SQLite Durable Object, and checks `/v1/info`.
It uses Cloudflare's [subdomain API](https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/methods/update/)
and Wrangler's [deployment secrets file](https://developers.cloudflare.com/workers/configuration/secrets/).
There is no separate database creation step or paid-plan upgrade.

For a new Worker, it generates separate setup and recovery enrollment tokens.
It saves them before deployment in an account-specific JSON file under
`.server-install/`, which Git ignores, and prints the file path and server URL.
Keep that file private and back it up. Unix file permissions are restricted;
on Windows, the directory inherits your checkout's access permissions.
Cloudflare login credentials are never saved in this file or printed by the script.

Open the extension's Synchronization screen and use the server URL and
`SETUP_TOKEN` from that file to create your vault. Vault encryption keys and the
encryption recovery secret are created by the extension. The server's
`RECOVERY_TOKEN` is a separate recovery enrollment credential.
The installer never bootstraps a temporary device or creates your vault.

Rerunning deploys code to the same production Worker and preserves all existing
remote secrets, including an intentionally absent setup token. It does not
recover unreadable remote secrets or guarantee that a local saved copy is current.
For an existing deployment, use your original credentials. Follow the bootstrap
instructions below to remove `SETUP_TOKEN` after creating the vault.

If you belong to several accounts, the entered domain selects its owning account.
For a new domain with multiple accounts, set `CLOUDFLARE_ACCOUNT_ID` before running.
The script never renames an existing account subdomain. Invalid input, unavailable
names, ambiguous accounts, or Cloudflare access errors stop with an error instead
of adding more prompts. Fix the issue and rerun. A failed first deployment reuses
its saved tokens. A failed discovery check leaves the deployment and credentials
intact so you can retry the displayed discovery URL.

Run the isolated installer tests without Cloudflare access:

```bash
npm run test:installer
```

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
ADVATAB_URL=http://127.0.0.1:8787 ADVATAB_SETUP_TOKEN=... npm run smoke
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

### Managed control RPC deployment

Deploy the backend before enabling the customer-management external namespace
binding. The backend Worker owns `VaultDurableObject`, its SQLite migrations,
the `VAULTS` namespace, and the typed `initializeManagedVault` and
`setEffectiveEntitlement` RPCs. Customer-management must bind to this class
with `script_name` and must not declare a local class, migration, or copied
data-plane implementation. Use the matching backend script name for each
environment (`geboom-sync-staging` or `geboom-sync-production`) and the
checked-in `spec/managed-vault-control-rpc-fixture.ts` as the contract.

Observe deployments with `npx wrangler tail --env staging` or the Workers
dashboard. Existing structured `request` and `vault_error` events cover the
Phase 2 data plane; control-plane callers should record the operation ID,
RPC method, result status, entitlement version, and latency without logging
credential key material, device private keys, recovery material, or plaintext
records. A failed or timed-out RPC is safe to retry with the same operation
ID.

To roll back, disable customer-management onboarding and managed gateway
traffic first, then deploy a known backend revision. Durable Object migrations
are forward-only: leave the managed-control tables and initialized objects in
place, and never delete or recycle reserved handles. Re-enable the gateway
only after the backend RPC and Phase 2 regression checks pass in the target
environment.

The manual GitHub deployment workflow requires protected GitHub Environments named `staging` and `production`, each configured with:

- secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`;
- variable `ADVATAB_URL` containing the deployed Worker URL;
- optional secret `ADVATAB_SETUP_TOKEN`, used only when smoke-testing a fresh deployment.

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
- `src/signatures.ts`: the documented RFC 9421 AdvaTab signature profile and a reusable WebCrypto signer.
- `src/validation.ts` and `src/protocol.ts`: dependency-free wire validation and public TypeScript contracts.
- `spec/phase2-wire-fixtures.md`: canonical cross-repository request, response, encoding, and signature fixtures.

The normative protocol is in `spec/01-sync-backend-spec.md`.
