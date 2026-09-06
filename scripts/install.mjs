import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workerName = 'geboom-sync-production';

export function normalizeDomain(value) {
  const name = value.trim().toLowerCase().replace(/\.workers\.dev\/?$/, '');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) {
    throw new Error('Enter an account subdomain such as klinki or klinki.workers.dev, without https:// or a Worker name.');
  }
  return name;
}

// Never rename an account subdomain: that would affect its other Workers.
export function selectAccount(accounts, domain, accountId) {
  const candidates = accountId ? accounts.filter((account) => account.id === accountId) : accounts;
  const matching = candidates.filter((account) => account.subdomain === domain);
  if (matching.length === 1) return matching[0];
  if (candidates.length === 1 && !candidates[0].subdomain) return candidates[0];
  throw new Error('The domain does not uniquely identify an accessible account. Use its existing workers.dev subdomain, or set CLOUDFLARE_ACCOUNT_ID for an account without one.');
}

function run(command, args, { capture = false, interactive = false, env = {} } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      shell: false,
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', ...env, ...(interactive ? {} : { CI: 'true' }) },
      stdio: [interactive ? 'inherit' : 'ignore', capture ? 'pipe' : 'inherit', capture ? 'pipe' : 'inherit'],
    });
    let output = '';
    if (capture) {
      child.stdout.on('data', (data) => { output += data; });
      // Auth output can contain credentials. Never echo captured output on failure.
      child.stderr.resume();
    }
    child.on('error', reject);
    child.on('close', (code) => code === 0
      ? resolveRun(output)
      : reject(new Error(`${args[0] === wranglerPath ? 'Wrangler' : 'Dependency installation'} failed with exit code ${code}.`)));
  });
}

const wranglerPath = join(root, 'node_modules/wrangler/bin/wrangler.js');
const wrangler = (args, options) => run(process.execPath, [wranglerPath, ...args], options);

export function cloudflareApi(auth, fetchFn = globalThis.fetch) {
  const headers = auth.type === 'api_key'
    ? { 'X-Auth-Key': auth.key, 'X-Auth-Email': auth.email }
    : { Authorization: `Bearer ${auth.token}` };
  return async (path, { method = 'GET', body, allowMissing = false } = {}) => {
    const response = await fetchFn(`https://api.cloudflare.com/client/v4${path}`, {
      method, headers: { ...headers, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
    const data = await response.json();
    if (allowMissing && data.errors?.some((error) => error.code === 10007)) return null;
    if (!response.ok || !data.success) {
      // Report codes only: response bodies can contain supplied secrets.
      throw new Error(`Cloudflare ${method} ${path} failed (${response.status}; codes ${data.errors?.map((error) => error.code).join(', ') || 'unknown'}). Check account access and domain availability.`);
    }
    return data.result;
  };
}

export async function provision({ domain, accounts, accountId, api, deploy, loadState, saveState, token = () => randomBytes(32).toString('base64url') }) {
  const available = [];
  for (const account of accounts) {
    if (accountId && account.id !== accountId) continue;
    const result = await api(`/accounts/${account.id}/workers/subdomain`, { allowMissing: true });
    available.push({ ...account, subdomain: result?.subdomain });
  }
  const account = selectAccount(available, domain, accountId);
  const base = `/accounts/${account.id}/workers`;
  if (!account.subdomain) {
    await api(`${base}/subdomain`, { method: 'PUT', body: { subdomain: domain } });
  }
  const target = `${account.id}-${workerName}`;
  const saved = await loadState(target);
  const remoteSecrets = await api(`${base}/scripts/${workerName}/secrets`, { allowMissing: true });
  const existing = new Set((remoteSecrets ?? []).map((secret) => secret.name));
  // An existing deployment's secrets belong to its owner, even if this machine
  // has an older copy. Preserve deliberately removed tokens as well.
  const secrets = {};
  for (const name of ['SETUP_TOKEN', 'RECOVERY_TOKEN']) {
    if (remoteSecrets === null) secrets[name] = saved?.secrets?.[name] ?? token();
  }
  const state = {
    accountId: account.id, workerName,
    serverUrl: `https://${workerName}.${domain}.workers.dev`,
    secrets: { ...saved?.secrets, ...secrets },
    preservedRemoteSecrets: [...existing],
  };
  // Persist before deployment so an interrupted run can reuse the same tokens.
  await saveState(target, state);
  await deploy(account.id, secrets);
  return state;
}

export async function verifyServer(url, fetchFn = globalThis.fetch, pause = (ms) => new Promise((done) => setTimeout(done, ms))) {
  for (let attempt = 0; attempt < 12; attempt++) {
    try {
      const response = await fetchFn(`${url}/v1/info`, { signal: AbortSignal.timeout(10_000) });
      const info = await response.json();
      if (response.ok && info.protocolVersions?.includes(1) && typeof info.setupRequired === 'boolean') return info;
    } catch { /* Allow workers.dev routing and DNS to propagate. */ }
    if (attempt < 11) await pause(5000);
  }
  throw new Error(`Deployment completed but discovery is not ready. Retry GET ${url}/v1/info shortly; saved credentials remain available.`);
}

async function main() {
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Install Node.js 22 or newer, then rerun this script.');
  console.log('Installing the locked project dependencies, including Wrangler…');
  const npmCli = [process.env.npm_execpath, join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')]
    .find((path) => path && existsSync(path));
  if (!npmCli) throw new Error('npm was not found. Install Node.js with npm, or run npm run install:server.');
  await run(process.execPath, [npmCli, 'ci', '--no-audit', '--no-fund']);

  console.log('Step 1 of 2: approve Wrangler login in your browser.');
  await wrangler(['login'], { interactive: true });
  const identity = JSON.parse(await wrangler(['whoami', '--json'], { capture: true }));
  const auth = JSON.parse(await wrangler(['auth', 'token', '--json'], { capture: true }));
  const input = createInterface({ input: process.stdin, output: process.stdout });
  let domain;
  try {
    domain = normalizeDomain(await input.question('Step 2 of 2: your Cloudflare account domain (e.g. klinki.workers.dev): '));
  } finally { input.close(); }

  const directory = join(root, '.server-install');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  let credentialsPath;
  const state = await provision({
    domain, accounts: identity.accounts, accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
    api: cloudflareApi(auth),
    loadState: async (target) => {
      try { return JSON.parse(await readFile(join(directory, `${target}.json`), 'utf8')); }
      catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    },
    saveState: async (target, state) => {
      credentialsPath = join(directory, `${target}.json`);
      await writeFile(credentialsPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    },
    deploy: async (accountId, secrets) => {
      const secretsPath = join(directory, 'deploy-secrets.json');
      await writeFile(secretsPath, JSON.stringify(secrets), { mode: 0o600 });
      console.log(`Deploying ${workerName} and its SQLite Durable Object…`);
      try {
        // Even an empty secrets file tells Wrangler to retain remote secrets.
        await wrangler(['deploy', '--env', 'production', '--secrets-file', secretsPath], {
          env: { CLOUDFLARE_ACCOUNT_ID: accountId },
        });
      } finally {
        // Keep the per-account credentials file; clear the transient upload file.
        await writeFile(secretsPath, '{}', { mode: 0o600 });
      }
    },
  });
  const info = await verifyServer(state.serverUrl);
  console.log(`Server ready: ${state.serverUrl}\nCredentials saved to: ${credentialsPath}`);
  console.log(info.setupRequired
    ? 'Open Synchronization in the extension, enter the server URL and SETUP_TOKEN, and create your vault.'
    : 'Your existing vault is ready. Pair a device or recover it from the extension.');
  console.log('Existing remote tokens were preserved. A saved copy of a preserved token may be stale. RECOVERY_TOKEN is an enrollment token, separate from your extension recovery secret.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
