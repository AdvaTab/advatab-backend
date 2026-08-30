export const PROTOCOL_VERSION = 1;
export const AUTH_ALGORITHM = 'ecdsa-p256-sha256';

export interface DeviceInput {
  deviceId: string;
  authAlgorithm: typeof AUTH_ALGORITHM;
  authPublicKey: string;
  metadataCiphertext?: string | null;
}

export interface BootstrapRequest {
  protocolVersion: number;
  vaultId: string;
  device: DeviceInput;
}

export interface SyncMutation {
  itemId: string;
  expectedRevision: number;
  deleted: boolean;
  cryptoVersion?: number;
  nonce?: string;
  ciphertext?: string;
}

export interface SyncRequest {
  protocolVersion: number;
  syncRequestId: string;
  cursor: number;
  mutations: SyncMutation[];
  limit?: number;
}

export interface SyncItem {
  itemId: string;
  revision: number;
  deleted: boolean;
  cryptoVersion?: number;
  nonce?: string;
  ciphertext?: string;
}

export type MutationResult =
  | { itemId: string; status: 'ok'; revision: number }
  | { itemId: string; status: 'conflict'; code?: 'tombstone_terminal'; current: SyncItem | null };

export interface SyncResponse {
  protocolVersion: 1;
  serverRevision: number;
  nextCursor: number;
  hasMore: boolean;
  mutationResults: MutationResult[];
  changes: SyncItem[];
}

export interface EnvelopeInput {
  type: string;
  credentialRef?: string | null;
  cryptoVersion: number;
  nonce?: string | null;
  ciphertext: string;
}

export interface PairingCreateRequest {
  protocolVersion: number;
  transferPublicKey: string;
  device: DeviceInput;
}

export interface PairingApproveRequest {
  transferPayload: string;
}
