import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cloudflareApi, normalizeDomain, provision, selectAccount, verifyServer } from './install.mjs';

test('accepts only account workers.dev names, without URLs or command syntax', () => {
  assert.equal(normalizeDomain(' Klinki.workers.dev '), 'klinki');
  assert.equal(normalizeDomain('new-account'), 'new-account');
  for (const value of ['', '-bad', 'https://klinki.workers.dev', 'worker.klinki.workers.dev', 'sync.example.com', 'x; whoami', 'a'.repeat(64)]) {
    assert.throws(() => normalizeDomain(value));
  }
});

test('selects matching account without renaming or guessing among new accounts', () => {
  const accounts = [{ id: 'a', subdomain: 'one' }, { id: 'b', subdomain: 'two' }];
  assert.equal(selectAccount(accounts, 'two').id, 'b');
  assert.throws(() => selectAccount(accounts, 'new'));
  assert.throws(() => selectAccount([{ id: 'a' }, { id: 'b' }], 'new'));
  assert.equal(selectAccount([{ id: 'a' }, { id: 'b' }], 'new', 'b').id, 'b');
  assert.throws(() => selectAccount(accounts, 'two', 'a'));
});

function fixture({ subdomain = 'demo', remoteSecrets = null, saved = null, failDeploy = false } = {}) {
  const events = [];
  const options = {
    domain: 'demo', accounts: [{ id: 'account' }], token: () => `token-${events.length}`,
    api: async (path, options) => {
      events.push({ path, ...options });
      if (path.endsWith('/subdomain')) return subdomain ? { subdomain } : null;
      if (path.endsWith('/secrets')) return remoteSecrets;
      throw new Error(`Unexpected API call ${path}`);
    },
    loadState: async () => saved,
    saveState: async (target, state) => { events.push({ save: state }); },
    deploy: async (account, secrets) => {
      events.push({ deploy: secrets });
      if (failDeploy) throw new Error('deployment failed');
    },
  };
  return { options, events };
}

test('fresh installation registers domain, saves tokens before deploying, never bootstraps', async () => {
  const { options, events } = fixture({ subdomain: null });
  const state = await provision(options);
  assert.equal(state.serverUrl, 'https://geboom-sync-production.demo.workers.dev');
  assert.equal(events.filter((event) => event.method === 'PUT').length, 1);
  assert.deepEqual(Object.keys(events.at(-1).deploy), ['SETUP_TOKEN', 'RECOVERY_TOKEN']);
  assert.ok(events.at(-2).save);
  assert.equal(events.some((event) => event.path?.includes('bootstrap')), false);
});

test('reruns preserve remote secrets and deliberately removed setup tokens', async () => {
  for (const remoteSecrets of [[], [{ name: 'RECOVERY_TOKEN' }], [{ name: 'SETUP_TOKEN' }, { name: 'RECOVERY_TOKEN' }]]) {
    const { options, events } = fixture({ remoteSecrets, saved: { secrets: { SETUP_TOKEN: 'old' } } });
    await provision(options);
    assert.deepEqual(events.at(-1).deploy, {});
    assert.equal(events.some((event) => event.method === 'PUT'), false);
  }
});

test('failed first deployment saves reusable tokens and reports failure', async () => {
  const saved = { secrets: { SETUP_TOKEN: 'original-setup', RECOVERY_TOKEN: 'original-recovery' } };
  const { options, events } = fixture({ saved, failDeploy: true });
  await assert.rejects(provision(options), /deployment failed/);
  assert.deepEqual(events.at(-2).save.secrets, saved.secrets);
  assert.deepEqual(events.at(-1).deploy, saved.secrets);
});

test('permission/API failures cannot be mistaken for a missing Worker', async () => {
  const denied = cloudflareApi({ type: 'oauth', token: 'private' }, async () => Response.json({ success: false, errors: [{ code: 10000, message: 'private' }] }, { status: 403 }));
  await assert.rejects(denied('/accounts/a/workers/subdomain', { allowMissing: true }), (error) => !error.message.includes('private') && error.message.includes('403'));
  const missing = cloudflareApi({ type: 'oauth', token: 'private' }, async () => Response.json({ success: false, errors: [{ code: 10007 }] }, { status: 404 }));
  assert.equal(await missing('/accounts/a/workers/subdomain', { allowMissing: true }), null);
});

test('health check retries discovery and makes only unauthenticated GET requests', async () => {
  let calls = 0;
  const info = await verifyServer('https://example.workers.dev', async (url, options) => {
    assert.equal(url, 'https://example.workers.dev/v1/info');
    assert.equal(options.headers, undefined);
    assert.equal(options.method, undefined);
    if (++calls === 1) throw new Error('DNS pending');
    return Response.json({ protocolVersions: [1], setupRequired: true });
  }, async () => {});
  assert.equal(calls, 2);
  assert.equal(info.setupRequired, true);
  await assert.rejects(verifyServer('https://example.workers.dev', async () => Response.json({}), async () => {}), /discovery is not ready/);
});
