import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;
const baseUrl = (process.env.SUPATABS_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');
const setupToken = process.env.SUPATABS_SETUP_TOKEN;
const base64 = (value) => Buffer.from(value).toString('base64');

async function sign(path, method, body, privateKey, deviceId, vaultHandle) {
  const bodyText = body === undefined ? undefined : JSON.stringify(body);
  const headers = new Headers(bodyText === undefined ? {} : { 'content-type': 'application/json' });
  headers.set('x-supatabs-device-id', deviceId);
  headers.set('x-supatabs-vault-handle', vaultHandle);
  headers.set('x-supatabs-request-id', crypto.randomUUID());
  const components = ['@method', '@path', '@query'];
  if (bodyText !== undefined) {
    const digest = base64(await subtle.digest('SHA-256', Buffer.from(bodyText)));
    headers.set('content-digest', `sha-256=:${digest}:`);
    components.push('content-digest');
  }
  components.push('x-supatabs-device-id', 'x-supatabs-vault-handle', 'x-supatabs-request-id');
  const created = Math.floor(Date.now() / 1000);
  const parameters = `(${components.map((value) => `"${value}"`).join(' ')});created=${created};expires=${created + 300};keyid="${deviceId}";alg="ecdsa-p256-sha256"`;
  headers.set('signature-input', `sig1=${parameters}`);
  const url = new URL(path, baseUrl);
  const values = {
    '@method': method.toLowerCase(),
    '@path': url.pathname,
    '@query': url.search || '?',
  };
  const lines = components.map((component) => `"${component}": ${values[component] ?? headers.get(component)}`);
  lines.push(`"@signature-params": ${parameters}`);
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, Buffer.from(lines.join('\n')));
  headers.set('signature', `sig1=:${base64(signature)}:`);
  return new Request(url, { method, headers, body: bodyText });
}

async function expectJson(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(`${response.status}: ${JSON.stringify(body)}`);
  return body;
}

const info = await expectJson(await fetch(`${baseUrl}/v1/info`));
console.log(`Connected to ${info.serverId}; setupRequired=${info.setupRequired}`);

if (!info.setupRequired) {
  console.log('Discovery passed. A bootstrapped vault requires existing device credentials for an authenticated smoke test.');
  process.exit(0);
}
if (!setupToken) throw new Error('Set SUPATABS_SETUP_TOKEN to bootstrap a fresh deployment.');

const keys = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicKey = base64(await subtle.exportKey('spki', keys.publicKey));
const deviceId = `smoke-${crypto.randomUUID()}`;
const bootstrap = await expectJson(await fetch(`${baseUrl}/v1/bootstrap/device`, {
  method: 'POST',
  headers: { authorization: `Bearer ${setupToken}`, 'content-type': 'application/json' },
  body: JSON.stringify({
    protocolVersion: 1,
    vaultId: `smoke-${crypto.randomUUID()}`,
    device: { deviceId, authAlgorithm: 'ecdsa-p256-sha256', authPublicKey: publicKey },
  }),
}));
const sync = await sign('/v1/sync', 'POST', {
  protocolVersion: 1,
  syncRequestId: crypto.randomUUID(),
  cursor: 0,
  mutations: [],
}, keys.privateKey, deviceId, bootstrap.vaultHandle);
const result = await expectJson(await fetch(sync));
console.log(`Bootstrap and signed sync passed; serverRevision=${result.serverRevision}`);
