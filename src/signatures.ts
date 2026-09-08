import { base64ToBytes, bytesToBase64, sha256Base64, toArrayBuffer, utf8 } from './encoding';
import { ApiError } from './errors';

export const DEVICE_HEADER = 'x-advatab-device-id';
export const VAULT_HEADER = 'x-advatab-vault-handle';
export const REQUEST_HEADER = 'x-advatab-request-id';

interface SignatureParameters {
  components: string[];
  componentList: string;
  created: number;
  expires: number;
  keyid: string;
  serialized: string;
}

const signatureInputPattern = /^sig1=\(([^)]*)\);created=(\d+);expires=(\d+);keyid="([A-Za-z0-9][A-Za-z0-9._:-]{0,127})";alg="ecdsa-p256-sha256"$/;

function parseSignatureInput(value: string | null): SignatureParameters {
  const match = value?.match(signatureInputPattern);
  if (!match) throw new ApiError('unauthorized', 'Invalid Signature-Input header.', 401);
  const components = [...(match[1]?.matchAll(/"([^"]+)"/g) ?? [])].map((entry) => entry[1] as string);
  return {
    components,
    componentList: match[1] as string,
    created: Number(match[2]),
    expires: Number(match[3]),
    keyid: match[4] as string,
    serialized: value!.slice('sig1='.length),
  };
}

function expectedComponents(hasBody: boolean): string[] {
  return [
    '@method',
    '@path',
    '@query',
    ...(hasBody ? ['content-digest'] : []),
    DEVICE_HEADER,
    VAULT_HEADER,
    REQUEST_HEADER,
  ];
}

function componentValue(component: string, request: Request): string {
  const url = new URL(request.url);
  if (component === '@method') return request.method.toLowerCase();
  if (component === '@path') return url.pathname;
  if (component === '@query') return url.search || '?';
  const value = request.headers.get(component);
  if (value === null) throw new ApiError('unauthorized', `Missing signed ${component} header.`, 401);
  return value.trim();
}

export function signatureBase(request: Request, parameters: SignatureParameters): string {
  const lines = parameters.components.map((component) => `"${component}": ${componentValue(component, request)}`);
  lines.push(`"@signature-params": ${parameters.serialized}`);
  return lines.join('\n');
}

export async function verifySignedRequest(
  request: Request,
  body: Uint8Array,
  publicKeySpki: Uint8Array,
  expectedDeviceId: string,
  windowSeconds: number,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<void> {
  const parameters = parseSignatureInput(request.headers.get('signature-input'));
  const hasBody = body.byteLength > 0;
  const expected = expectedComponents(hasBody);
  if (parameters.components.length !== expected.length || parameters.components.some((value, index) => value !== expected[index])) {
    throw new ApiError('unauthorized', 'Signature does not use the AdvaTab v1 component profile.', 401);
  }
  if (parameters.componentList !== expected.map((value) => `"${value}"`).join(' ')) {
    throw new ApiError('unauthorized', 'Signature component serialization is invalid.', 401);
  }
  const deviceId = request.headers.get(DEVICE_HEADER);
  if (!deviceId || deviceId !== expectedDeviceId || parameters.keyid !== deviceId) throw new ApiError('unauthorized', 'Signature key does not match device.', 401);
  if (parameters.expires < parameters.created || parameters.expires - parameters.created > windowSeconds) {
    throw new ApiError('signature_expired', 'Signature validity window is invalid.', 401);
  }
  if (parameters.created > nowSeconds + 30 || parameters.expires < nowSeconds - 30) {
    throw new ApiError('signature_expired', 'Signature is outside its validity window.', 401);
  }
  if (hasBody) {
    const digest = `sha-256=:${await sha256Base64(body)}:`;
    if (request.headers.get('content-digest') !== digest) throw new ApiError('unauthorized', 'Content-Digest does not match the request body.', 401);
  }
  const signatureMatch = request.headers.get('signature')?.match(/^sig1=:([A-Za-z0-9+/]+={0,2}):$/);
  if (!signatureMatch) throw new ApiError('unauthorized', 'Invalid Signature header.', 401);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('spki', toArrayBuffer(publicKeySpki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  } catch {
    throw new ApiError('unauthorized', 'Stored device key is invalid.', 401);
  }
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    toArrayBuffer(base64ToBytes(signatureMatch[1] as string, 'Signature')),
    toArrayBuffer(utf8(signatureBase(request, parameters))),
  );
  if (!valid) throw new ApiError('unauthorized', 'Request signature is invalid.', 401);
}

export async function signRequest(request: Request, privateKey: CryptoKey, deviceId: string, vaultHandle: string, nowSeconds = Math.floor(Date.now() / 1000)): Promise<Request> {
  const body = new Uint8Array(await request.clone().arrayBuffer());
  const headers = new Headers(request.headers);
  headers.set(DEVICE_HEADER, deviceId);
  headers.set(VAULT_HEADER, vaultHandle);
  if (!headers.has(REQUEST_HEADER)) headers.set(REQUEST_HEADER, crypto.randomUUID());
  if (body.byteLength > 0) headers.set('content-digest', `sha-256=:${await sha256Base64(body)}:`);
  const components = expectedComponents(body.byteLength > 0);
  const serialized = `(${components.map((value) => `"${value}"`).join(' ')});created=${nowSeconds};expires=${nowSeconds + 300};keyid="${deviceId}";alg="ecdsa-p256-sha256"`;
  headers.set('signature-input', `sig1=${serialized}`);
  const requestInit: RequestInit = {
    method: request.method,
    headers,
    body: body.byteLength > 0 ? toArrayBuffer(body) : undefined,
  };
  const unsigned = new Request(request.url, requestInit);
  const parameters: SignatureParameters = { components, componentList: components.map((value) => `"${value}"`).join(' '), created: nowSeconds, expires: nowSeconds + 300, keyid: deviceId, serialized };
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, toArrayBuffer(utf8(signatureBase(unsigned, parameters)))));
  headers.set('signature', `sig1=:${bytesToBase64(signature)}:`);
  return new Request(request.url, { ...requestInit, headers });
}
