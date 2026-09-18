import { sha256Base64Url, utf8 } from './encoding';
import type { AUTH_ALGORITHM } from './protocol';

export type ManagedControlMethod =
  | 'initializeManagedVault'
  | 'setEffectiveEntitlement'
  | 'verifyManagedPasskey'
  | 'recoverManagedDevice'
  | 'storeManagedRecoveryGeneration'
  | 'hasManagedRecoveryGeneration'
  | 'confirmManagedRecoveryGeneration';

export type ManagedAccessMode = 'read_write' | 'read_only';
export type ManagedTier = 'tester' | 'pro' | null;

export interface ManagedCredential {
  credentialId: string;
  publicKey: string;
  signCount: number;
}

export interface ManagedDevice {
  deviceId: string;
  authAlgorithm: typeof AUTH_ALGORITHM;
  authPublicKey: string;
}

/** The JSON-safe WebAuthn assertion shape accepted by the internal RPC. */
export interface ManagedPasskeyAssertion {
  id: string;
  rawId?: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
  };
}

export interface ManagedRecoveryEnvelope {
  type: 'recovery-v1';
  cryptoVersion: 1;
  nonce: string;
  ciphertext: string;
}

export interface EffectiveEntitlement {
  product: string;
  tier: ManagedTier;
  mode: ManagedAccessMode;
  validUntil: string | null;
  version: number;
}

export interface InitializeManagedVaultRequest {
  operationId: string;
  vaultId: string;
  credential: ManagedCredential;
  device: ManagedDevice;
  effectiveEntitlement: EffectiveEntitlement;
}

export interface InitializeManagedVaultResult {
  status: 'initialized';
  vaultHandle: string;
  entitlementVersion: number;
}

export interface SetEffectiveEntitlementRequest {
  operationId: string;
  product: string;
  tier: ManagedTier;
  mode: ManagedAccessMode;
  validUntil: string | null;
  version: number;
}

export interface SetEffectiveEntitlementResult {
  applied: boolean;
  entitlementVersion: number;
}

export interface VerifyManagedPasskeyRequest {
  operationId: string;
  /** The routing handle supplied by customer-management, encoded as DO-ID hex. */
  userHandle?: string;
  /** Legacy names remain accepted while callers migrate to the shared contract. */
  expectedChallenge?: string;
  expectedRpId?: string;
  challenge?: string;
  rpId?: string;
  expectedOrigin: string;
  assertion: ManagedPasskeyAssertion;
}

export interface VerifyManagedPasskeyResult {
  verified: true;
  vaultId: string;
  vaultHandle: string;
  credentialId: string;
  signCount: number;
  /** Compatibility fields retained for early managed-client fixtures. */
  status?: 'verified';
  protocolVersion?: number;
  effectiveEntitlement?: EffectiveEntitlement;
}

export interface RecoverManagedDeviceRequest {
  operationId: string;
  generation?: number;
  recoveryGeneration?: number;
  vaultId?: string;
  device: ManagedDevice;
}

export interface RecoverManagedDeviceResult {
  status: 'recovered';
  vaultId: string;
  vaultHandle: string;
  deviceId: string;
  encryptedRecoveryEnvelope: ManagedRecoveryEnvelope;
  recoveryEnvelope?: ManagedRecoveryEnvelope;
  protocolVersion: number;
  effectiveEntitlement: EffectiveEntitlement;
}

export interface StoreManagedRecoveryGenerationRequest {
  operationId: string;
  generation: number;
  encryptedRecoveryEnvelope?: ManagedRecoveryEnvelope;
  recoveryEnvelope?: ManagedRecoveryEnvelope;
}

export interface StoreManagedRecoveryGenerationResult {
  stored: boolean;
  generation: number;
}

export interface HasManagedRecoveryGenerationRequest {
  generation: number;
  /** Optional for the read-only availability probe; callers may supply one to make the probe auditable/idempotent. */
  operationId?: string;
}

export interface HasManagedRecoveryGenerationResult {
  available: boolean;
}

export interface ConfirmManagedRecoveryGenerationResult extends HasManagedRecoveryGenerationResult {
  generation: number;
}

export type VerifyManagedPasskeyInput = VerifyManagedPasskeyRequest;
export type ConfirmManagedRecoveryGenerationInput = HasManagedRecoveryGenerationRequest;
export type StoreManagedRecoveryGenerationInput = StoreManagedRecoveryGenerationRequest;
export type RecoverManagedDeviceInput = RecoverManagedDeviceRequest;

export interface ManagedVaultControlRpc {
  initializeManagedVault(input: InitializeManagedVaultRequest): Promise<InitializeManagedVaultResult>;
  setEffectiveEntitlement(input: SetEffectiveEntitlementRequest): Promise<SetEffectiveEntitlementResult>;
  verifyManagedPasskey(input: VerifyManagedPasskeyRequest): Promise<VerifyManagedPasskeyResult>;
  confirmManagedRecoveryGeneration(input: HasManagedRecoveryGenerationRequest): Promise<ConfirmManagedRecoveryGenerationResult>;
  recoverManagedDevice(input: RecoverManagedDeviceRequest): Promise<RecoverManagedDeviceResult>;
  storeManagedRecoveryGeneration(input: StoreManagedRecoveryGenerationRequest): Promise<StoreManagedRecoveryGenerationResult>;
  hasManagedRecoveryGeneration(input: HasManagedRecoveryGenerationRequest): Promise<HasManagedRecoveryGenerationResult>;
}

export function effectiveAccessMode(mode: ManagedAccessMode, validUntil: string | null, now = Date.now()): ManagedAccessMode {
  return validUntil !== null && Date.parse(validUntil) <= now ? 'read_only' : mode;
}

export interface ControlOperationRow {
  operation_id: string;
  method: ManagedControlMethod;
  input_hash: string;
  result_json: string;
  created_at: string;
}

export class ManagedControlConflictError extends Error {
  readonly code = 'managed_control_conflict';

  constructor(message: string) {
    super(message);
    this.name = 'ManagedControlConflictError';
  }
}

type Sql = DurableObjectState['storage']['sql'];

function canonicalValue(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Managed control inputs must contain only finite numbers.');
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => canonicalValue(entry));
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, entry]) => [key, canonicalValue(entry)]));
  }
  throw new TypeError('Managed control inputs must contain only JSON values.');
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export async function immutableInputHash(value: unknown): Promise<string> {
  return sha256Base64Url(utf8(canonicalJson(value)));
}

export function getControlOperation<T>(sql: Sql, operationId: string, method: ManagedControlMethod, inputHash: string): T | null {
  const row = sql.exec(
    'SELECT operation_id, method, input_hash, result_json, created_at FROM managed_control_operations WHERE operation_id = ?',
    operationId,
  ).toArray()[0] as ControlOperationRow | undefined;
  if (!row) return null;
  if (row.method !== method || row.input_hash !== inputHash) {
    throw new ManagedControlConflictError(`Operation ${operationId} was already used for different control inputs.`);
  }
  return JSON.parse(row.result_json) as T;
}

export function storeControlOperation(
  sql: Sql,
  operationId: string,
  method: ManagedControlMethod,
  inputHash: string,
  result: unknown,
  createdAt: string,
): void {
  sql.exec(
    'INSERT INTO managed_control_operations(operation_id, method, input_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?)',
    operationId,
    method,
    inputHash,
    JSON.stringify(result),
    createdAt,
  );
}
