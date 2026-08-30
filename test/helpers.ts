import { bytesToBase64 } from '../src/encoding';
import { signRequest } from '../src/signatures';

export interface TestDevice {
  deviceId: string;
  privateKey: CryptoKey;
  publicKey: string;
}

export async function createDevice(deviceId: string): Promise<TestDevice> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));
  return { deviceId, privateKey: pair.privateKey, publicKey };
}

export function jsonRequest(path: string, method: string, body?: unknown, headers?: HeadersInit): Request {
  return new Request(`https://sync.test${path}`, {
    method,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function signedRequest(path: string, method: string, device: TestDevice, vaultHandle: string, body?: unknown): Promise<Request> {
  return signRequest(jsonRequest(path, method, body), device.privateKey, device.deviceId, vaultHandle);
}

export async function responseJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}
