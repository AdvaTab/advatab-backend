import { base64UrlToBytes, toArrayBuffer, utf8 } from './encoding';
import type { ManagedCredential, ManagedPasskeyAssertion } from './managed-control';

type CborValue = number | Uint8Array<ArrayBuffer> | string | boolean | null | CborValue[] | Map<unknown, CborValue>;

class CborReader {
  private offset = 0;

  constructor(private readonly input: Uint8Array<ArrayBuffer>) {}

  read(): CborValue {
    const initial = this.byte();
    const major = initial >> 5;
    const additional = initial & 0x1f;
    if (additional === 31) throw new Error('Indefinite-length CBOR is not supported.');
    switch (major) {
      case 0: return this.length(additional);
      case 1: return -1 - this.length(additional);
      case 2: return this.bytes(this.length(additional));
      case 3: return new TextDecoder().decode(this.bytes(this.length(additional)));
      case 4: return Array.from({ length: this.length(additional) }, () => this.read());
      case 5: {
        const result = new Map<unknown, CborValue>();
        const count = this.length(additional);
        for (let index = 0; index < count; index += 1) result.set(this.read(), this.read());
        return result;
      }
      case 6:
        // COSE_Key does not use tags, but safely parse and ignore a tag if one
        // is supplied by a compatible authenticator.
        this.length(additional);
        return this.read();
      case 7:
        if (additional === 20) return false;
        if (additional === 21) return true;
        if (additional === 22) return null;
        throw new Error('Unsupported CBOR simple value.');
      default: throw new Error('Unsupported CBOR major type.');
    }
  }

  ensureDone(): void {
    if (this.offset !== this.input.byteLength) throw new Error('Trailing CBOR data.');
  }

  private byte(): number {
    const value = this.input[this.offset];
    if (value === undefined) throw new Error('Truncated CBOR.');
    this.offset += 1;
    return value;
  }

  private length(additional: number): number {
    if (additional < 24) return additional;
    const bytes = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (!bytes) throw new Error('Unsupported CBOR length.');
    let value = 0;
    for (let index = 0; index < bytes; index += 1) {
      value = value * 256 + this.byte();
      if (!Number.isSafeInteger(value)) throw new Error('CBOR length is too large.');
    }
    // Canonical CBOR requires the shortest length encoding. Rejecting a
    // non-canonical credential avoids accepting ambiguous key bytes.
    if ((bytes === 1 && value < 24) || (bytes === 2 && value <= 0xff) || (bytes === 4 && value <= 0xffff) || (bytes === 8 && value <= 0xffffffff)) {
      throw new Error('Non-canonical CBOR length.');
    }
    return value;
  }

  private bytes(length: number): Uint8Array<ArrayBuffer> {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.input.byteLength) throw new Error('Truncated CBOR bytes.');
    const result = this.input.slice(this.offset, this.offset + length) as Uint8Array<ArrayBuffer>;
    this.offset += length;
    return result;
  }
}

function asBytes(value: CborValue | undefined, field: string, length: number): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new Error(`Invalid COSE ${field}.`);
  return value;
}

async function importCredentialKey(publicKey: string): Promise<CryptoKey> {
  const reader = new CborReader(base64UrlToBytes(publicKey, 'credential.publicKey'));
  const value = reader.read();
  reader.ensureDone();
  if (!(value instanceof Map) || value.get(1) !== 2 || value.get(3) !== -7 || value.get(-1) !== 1) {
    throw new Error('Managed credential is not an ES256 COSE key.');
  }
  const x = asBytes(value.get(-2), 'x coordinate', 32);
  const y = asBytes(value.get(-3), 'y coordinate', 32);
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  return crypto.subtle.importKey('raw', toArrayBuffer(raw), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(left.byteLength + right.byteLength);
  result.set(left, 0);
  result.set(right, left.byteLength);
  return result as Uint8Array<ArrayBuffer>;
}

export function derToRaw(signature: Uint8Array): Uint8Array<ArrayBuffer> {
  if (signature[0] !== 0x30) throw new Error('Not a DER signature.');
  let offset = 1;
  const lengthByte = signature[offset++];
  if (lengthByte === undefined) throw new Error('Truncated DER signature.');
  let length: number;
  if (lengthByte < 0x80) length = lengthByte;
  else {
    const lengthBytes = lengthByte & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 2 || offset + lengthBytes > signature.byteLength) throw new Error('Invalid DER signature length.');
    length = 0;
    for (let index = 0; index < lengthBytes; index += 1) length = length * 256 + (signature[offset++] as number);
  }
  if (offset + length !== signature.byteLength) throw new Error('Invalid DER signature.');
  const readInteger = (): Uint8Array => {
    if (signature[offset++] !== 0x02) throw new Error('Invalid DER signature integer.');
    const size = signature[offset++];
    if (size === undefined || size === 0 || offset + size > signature.byteLength) throw new Error('Invalid DER signature integer length.');
    const result = signature.slice(offset, offset + size);
    offset += size;
    if (result.length === 33 && (result[0] !== 0 || (result[1]! & 0x80) === 0)) throw new Error('Invalid DER signature integer encoding.');
    if (result[0] === 0 && result.length > 1 && (result[1]! & 0x80) === 0) throw new Error('Non-canonical DER signature integer.');
    if ((result[0]! & 0x80) !== 0) throw new Error('Negative DER signature integer.');
    return result;
  };
  const r = readInteger();
  const s = readInteger();
  if (offset !== signature.byteLength || r.length > 33 || s.length > 33) throw new Error('Invalid DER signature.');
  const raw = new Uint8Array(64);
  raw.set(r.subarray(r.length > 32 ? 1 : 0), 32 - Math.min(32, r.length));
  raw.set(s.subarray(s.length > 32 ? 1 : 0), 64 - Math.min(32, s.length));
  return raw as Uint8Array<ArrayBuffer>;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function parseClientData(value: Uint8Array, expected: { challenge: string; origin: string }): void {
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder().decode(value)); } catch { throw new Error('WebAuthn client data is invalid.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('WebAuthn client data is invalid.');
  const record = parsed as Record<string, unknown>;
  if (record.type !== 'webauthn.get' || record.challenge !== expected.challenge || record.origin !== expected.origin || record.crossOrigin === true) {
    throw new Error('WebAuthn ceremony context is invalid.');
  }
}

function parseAssertionId(assertion: ManagedPasskeyAssertion): Uint8Array<ArrayBuffer> {
  const id = base64UrlToBytes(assertion.rawId ?? assertion.id, 'assertion credential ID');
  const serializedId = base64UrlToBytes(assertion.id, 'assertion id');
  if (!equalBytes(id, serializedId)) throw new Error('WebAuthn credential IDs do not match.');
  return id;
}

export async function verifyManagedAssertion(
  assertion: ManagedPasskeyAssertion,
  credential: ManagedCredential,
  expected: { challenge: string; rpId: string; origin: string; vaultHandle: Uint8Array },
): Promise<number> {
  if (assertion.type !== 'public-key' || !assertion.response) throw new Error('WebAuthn assertion is invalid.');
  const credentialId = parseAssertionId(assertion);
  const storedCredentialId = base64UrlToBytes(credential.credentialId, 'credential.credentialId');
  if (!equalBytes(credentialId, storedCredentialId)) throw new Error('WebAuthn credential ID is not registered.');
  const clientDataJSON = base64UrlToBytes(assertion.response.clientDataJSON, 'clientDataJSON');
  const authenticatorData = base64UrlToBytes(assertion.response.authenticatorData, 'authenticatorData');
  const signature = base64UrlToBytes(assertion.response.signature, 'signature');
  const userHandle = base64UrlToBytes(assertion.response.userHandle ?? '', 'userHandle');
  if (userHandle.byteLength !== 32 || !equalBytes(userHandle, expected.vaultHandle)) throw new Error('WebAuthn user handle is invalid.');
  if (authenticatorData.byteLength < 37) throw new Error('WebAuthn authenticator data is invalid.');
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(utf8(expected.rpId))));
  if (!equalBytes(authenticatorData.subarray(0, 32), rpIdHash)) throw new Error('WebAuthn RP ID is invalid.');
  const flags = authenticatorData[32]!;
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) throw new Error('WebAuthn user presence or verification is missing.');
  const counter = new DataView(toArrayBuffer(authenticatorData.subarray(33, 37))).getUint32(0);
  parseClientData(clientDataJSON, expected);
  const key = await importCredentialKey(credential.publicKey);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(clientDataJSON)));
  const signedData = concat(authenticatorData, clientDataHash);
  let valid = false;
  const signatureCandidates: Uint8Array[] = [signature];
  if (signature.byteLength !== 64) {
    try { signatureCandidates.unshift(derToRaw(signature)); } catch { /* verification below reports the failure */ }
  }
  for (const candidate of signatureCandidates) {
    try {
      valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, toArrayBuffer(candidate), toArrayBuffer(signedData));
    } catch {
      valid = false;
    }
    if (valid) break;
  }
  if (!valid) throw new Error('WebAuthn assertion signature is invalid.');
  return counter;
}
