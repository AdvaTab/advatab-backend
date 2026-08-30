import { base64ToBytes } from './encoding';
import { ApiError, invalid } from './errors';
import {
  AUTH_ALGORITHM,
  PROTOCOL_VERSION,
  type BootstrapRequest,
  type DeviceInput,
  type EnvelopeInput,
  type PairingApproveRequest,
  type PairingCreateRequest,
  type SyncMutation,
  type SyncRequest,
} from './protocol';
import type { Limits } from './config';

type JsonObject = Record<string, unknown>;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TYPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const maxBase64Length = (bytes: number): number => Math.ceil(bytes / 3) * 4;

const object = (value: unknown, field = 'body'): JsonObject => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(`${field} must be an object.`);
  return value as JsonObject;
};

const string = (value: unknown, field: string, max = 256): string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    invalid(`${field} must be a non-empty string of at most ${max} characters.`);
  }
  return value as string;
};

const id = (value: unknown, field: string): string => {
  const result = string(value, field, 128);
  if (!ID.test(result)) invalid(`${field} contains unsupported characters.`);
  return result;
};

const integer = (value: unknown, field: string, minimum = 0): number => {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) invalid(`${field} must be a safe integer >= ${minimum}.`);
  return value as number;
};

const protocolVersion = (value: unknown): number => {
  const version = integer(value, 'protocolVersion', 1);
  if (version !== PROTOCOL_VERSION) throw new ApiError('unsupported_protocol', 'Only protocol version 1 is supported.', 400);
  return version;
};

function device(value: unknown, limits: Limits): DeviceInput {
  const source = object(value, 'device');
  const authAlgorithm = string(source.authAlgorithm, 'device.authAlgorithm', 64);
  if (authAlgorithm !== AUTH_ALGORITHM) invalid(`device.authAlgorithm must be ${AUTH_ALGORITHM}.`);
  const authPublicKey = string(source.authPublicKey, 'device.authPublicKey', 4096);
  const publicKey = base64ToBytes(authPublicKey, 'device.authPublicKey');
  if (publicKey.byteLength < 64 || publicKey.byteLength > 1024) invalid('device.authPublicKey has an invalid SPKI size.');
  let metadataCiphertext: string | null | undefined;
  if (source.metadataCiphertext !== undefined && source.metadataCiphertext !== null) {
    metadataCiphertext = string(source.metadataCiphertext, 'device.metadataCiphertext', maxBase64Length(limits.maxItemBytes));
    if (base64ToBytes(metadataCiphertext, 'device.metadataCiphertext').byteLength > limits.maxItemBytes) {
      throw new ApiError('payload_too_large', 'Device metadata exceeds maxItemBytes.', 413);
    }
  } else {
    metadataCiphertext = source.metadataCiphertext as null | undefined;
  }
  return { deviceId: id(source.deviceId, 'device.deviceId'), authAlgorithm: AUTH_ALGORITHM, authPublicKey, metadataCiphertext };
}

export function parseBootstrap(value: unknown, limits: Limits): BootstrapRequest {
  const source = object(value);
  return { protocolVersion: protocolVersion(source.protocolVersion), vaultId: id(source.vaultId, 'vaultId'), device: device(source.device, limits) };
}

function mutation(value: unknown, limits: Limits): SyncMutation {
  const source = object(value, 'mutation');
  const deletedValue = source.deleted;
  if (typeof deletedValue !== 'boolean') invalid('mutation.deleted must be boolean.');
  const deleted = deletedValue as boolean;
  const result: SyncMutation = {
    itemId: id(source.itemId, 'mutation.itemId'),
    expectedRevision: integer(source.expectedRevision, 'mutation.expectedRevision'),
    deleted,
  };
  if (deleted) {
    if (source.cryptoVersion !== undefined || source.nonce !== undefined || source.ciphertext !== undefined) {
      invalid('Deleted mutations must not contain cryptoVersion, nonce, or ciphertext.');
    }
    return result;
  }
  result.cryptoVersion = integer(source.cryptoVersion, 'mutation.cryptoVersion', 1);
  result.nonce = string(source.nonce, 'mutation.nonce', 1024);
  result.ciphertext = string(source.ciphertext, 'mutation.ciphertext', maxBase64Length(limits.maxItemBytes));
  base64ToBytes(result.nonce, 'mutation.nonce');
  if (base64ToBytes(result.ciphertext, 'mutation.ciphertext').byteLength > limits.maxItemBytes) {
    throw new ApiError('payload_too_large', 'Mutation ciphertext exceeds maxItemBytes.', 413);
  }
  return result;
}

export function parseSync(value: unknown, limits: Limits): SyncRequest {
  const source = object(value);
  protocolVersion(source.protocolVersion);
  const mutationValues = source.mutations;
  if (!Array.isArray(mutationValues)) invalid('mutations must be an array.');
  const mutationArray = mutationValues as unknown[];
  if (mutationArray.length > limits.maxMutationsPerSync) throw new ApiError('payload_too_large', 'Too many mutations.', 413);
  const mutations = mutationArray.map((entry: unknown) => mutation(entry, limits));
  if (new Set(mutations.map((entry) => entry.itemId)).size !== mutations.length) invalid('A sync request may contain each itemId only once.');
  const requestedLimit = source.limit === undefined ? limits.maxResponseItems : integer(source.limit, 'limit', 1);
  return {
    protocolVersion: PROTOCOL_VERSION,
    syncRequestId: id(source.syncRequestId, 'syncRequestId'),
    cursor: integer(source.cursor, 'cursor'),
    mutations,
    limit: Math.min(requestedLimit, limits.maxResponseItems),
  };
}

export function parseEnvelope(value: unknown, limits: Limits): EnvelopeInput {
  const source = object(value);
  const type = string(source.type, 'type', 64);
  if (!TYPE.test(type)) invalid('type contains unsupported characters.');
  const ciphertext = string(source.ciphertext, 'ciphertext', maxBase64Length(limits.maxItemBytes));
  if (base64ToBytes(ciphertext, 'ciphertext').byteLength > limits.maxItemBytes) throw new ApiError('payload_too_large', 'Envelope ciphertext exceeds maxItemBytes.', 413);
  let nonce: string | null | undefined;
  if (source.nonce !== undefined && source.nonce !== null) {
    nonce = string(source.nonce, 'nonce', 1024);
    base64ToBytes(nonce, 'nonce');
  } else nonce = source.nonce as null | undefined;
  const credentialRef = source.credentialRef === null || source.credentialRef === undefined ? source.credentialRef : string(source.credentialRef, 'credentialRef', 512);
  return { type, credentialRef: credentialRef as string | null | undefined, cryptoVersion: integer(source.cryptoVersion, 'cryptoVersion', 1), nonce, ciphertext };
}

export function parsePairingCreate(value: unknown, limits: Limits): PairingCreateRequest {
  const source = object(value);
  protocolVersion(source.protocolVersion);
  const transferPublicKey = string(source.transferPublicKey, 'transferPublicKey', 4096);
  base64ToBytes(transferPublicKey, 'transferPublicKey');
  return { protocolVersion: PROTOCOL_VERSION, transferPublicKey, device: device(source.device, limits) };
}

export function parsePairingApprove(value: unknown, limits: Limits): PairingApproveRequest {
  const source = object(value);
  const transferPayload = string(source.transferPayload, 'transferPayload', maxBase64Length(limits.maxItemBytes));
  if (base64ToBytes(transferPayload, 'transferPayload').byteLength > limits.maxItemBytes) throw new ApiError('payload_too_large', 'Transfer payload exceeds maxItemBytes.', 413);
  return { transferPayload };
}

export function parseId(value: string, field: string): string {
  try {
    return id(decodeURIComponent(value), field);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    return invalid(`${field} must be valid URL-encoded text.`);
  }
}
