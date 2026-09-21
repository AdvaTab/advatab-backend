import { defaultVaultName, getLimits } from './config';
import { sha256Base64Url, utf8 } from './encoding';
import { ApiError, errorResponse } from './errors';
import { VAULT_HEADER } from './signatures';
import type { RuntimeEnv } from './env';
import { buildInfo } from './build-info.generated';
import { routeTemplate } from './usage-metering';

export { VaultDurableObject } from './vault';
export type { ManagedVaultControlRpc } from './managed-control';

const corsHeaders: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'access-control-allow-headers': [
    'authorization',
    'content-type',
    'content-digest',
    'signature',
    'signature-input',
    'x-advatab-device-id',
    'x-advatab-vault-handle',
    'x-advatab-request-id',
  ].join(', '),
  'access-control-max-age': '86400',
};

function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders)) headers.set(key, value);
  headers.set('vary', 'Origin');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function isDefaultRoute(method: string, pathname: string): boolean {
  if (method === 'GET' && pathname === '/v1/info') return true;
  if (method === 'POST' && pathname === '/v1/bootstrap/device') return true;
  if (method === 'POST' && pathname === '/v1/recovery/device') return true;
  if (method === 'POST' && pathname === '/v1/pairings') return true;
  if (method === 'GET' && /^\/v1\/pairings\/[^/]+$/.test(pathname) && pathname !== '/v1/pairings/pending') return true;
  return method === 'POST' && /^\/v1\/pairings\/[^/]+\/consume$/.test(pathname);
}

async function requestBody(request: Request, maxBytes: number): Promise<Uint8Array> {
  const contentLength = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(contentLength) && contentLength > maxBytes) throw new ApiError('payload_too_large', 'Request body exceeds maxRequestBytes.', 413);
  if (request.method === 'GET' || request.method === 'DELETE' || request.method === 'OPTIONS') return new Uint8Array();
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.byteLength > maxBytes) throw new ApiError('payload_too_large', 'Request body exceeds maxRequestBytes.', 413);
  return body;
}

async function errorCode(response: Response): Promise<string | undefined> {
  if (response.ok) return undefined;
  try {
    const value = (await response.clone().json()) as { error?: { code?: string } };
    return value.error?.code;
  } catch {
    return undefined;
  }
}

export default {
  async fetch(request: Request, env: RuntimeEnv): Promise<Response> {
    const started = Date.now();
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return withCors(new Response(null, { status: 204 }));
    if (request.method === 'GET' && url.pathname === '/api/about/version') {
      return withCors(Response.json(buildInfo, { headers: { 'cache-control': 'no-store' } }));
    }
    let response: Response;
    let requestBytes = 0;
    try {
      const limits = getLimits(env);
      const body = await requestBody(request, limits.maxRequestBytes);
      requestBytes = body.byteLength;
      const id = env.VAULTS.idFromName(defaultVaultName(env));
      const handle = id.toString();
      if (!isDefaultRoute(request.method, url.pathname) && request.headers.get(VAULT_HEADER) !== handle) {
        throw new ApiError('vault_not_found', 'The vault handle is not valid for this single-vault deployment.', 404);
      }
      const headers = new Headers(request.headers);
      const source = request.headers.get('cf-connecting-ip') || 'local';
      headers.set('x-advatab-internal-source', await sha256Base64Url(utf8(source)));
      headers.delete('cf-connecting-ip');
      const forwarded = new Request(request.url, {
        method: request.method,
        headers,
        body: body.byteLength > 0 ? body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer : undefined,
      });
      response = await env.VAULTS.get(id).fetch(forwarded);
    } catch (error) {
      response = errorResponse(error instanceof ApiError ? error : new ApiError('internal_error', 'An internal error occurred.', 500));
    }
    const code = await errorCode(response);
    console.log(JSON.stringify({
      event: 'request',
      method: request.method,
      route: routeTemplate(url.pathname),
      status: response.status,
      errorCode: code,
      requestBytes,
      responseBytes: Number(response.headers.get('content-length')) || undefined,
      durationMs: Date.now() - started,
    }));
    return withCors(response);
  },
} satisfies ExportedHandler<RuntimeEnv>;
