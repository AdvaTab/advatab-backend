import { ApiError } from './errors';

const encoder = new TextEncoder();

export const utf8 = (value: string): Uint8Array<ArrayBuffer> => encoder.encode(value) as Uint8Array<ArrayBuffer>;

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(value: string, field = 'value'): Uint8Array<ArrayBuffer> {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new ApiError('invalid_request', `${field} must be canonical padded base64.`);
  }
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)) as Uint8Array<ArrayBuffer>;
  } catch {
    throw new ApiError('invalid_request', `${field} must be valid base64.`);
  }
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function base64UrlToBytes(value: string, field = 'value'): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new ApiError('invalid_request', `${field} must be canonical base64url.`);
  }
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
  try {
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0)) as Uint8Array<ArrayBuffer>;
  } catch {
    throw new ApiError('invalid_request', `${field} must be valid base64url.`);
  }
}

export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

export async function sha256(bytes: BufferSource | Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const source = bytes instanceof Uint8Array ? toArrayBuffer(bytes) : bytes;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', source));
}

export async function sha256Base64(bytes: BufferSource | Uint8Array): Promise<string> {
  return bytesToBase64(await sha256(bytes));
}

export async function sha256Base64Url(bytes: BufferSource | Uint8Array): Promise<string> {
  return bytesToBase64Url(await sha256(bytes));
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = utf8(left);
  const b = utf8(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index++) {
    difference |= (a[index % a.length] ?? 0) ^ (b[index % b.length] ?? 0);
  }
  return difference === 0;
}
