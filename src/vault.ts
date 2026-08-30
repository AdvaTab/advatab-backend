import { DurableObject } from 'cloudflare:workers';
import { getLimits, type Limits } from './config';
import { base64ToBytes, bytesToBase64, bytesToBase64Url, constantTimeEqual, sha256Base64, sha256Base64Url, utf8 } from './encoding';
import { ApiError, errorResponse } from './errors';
import {
  AUTH_ALGORITHM,
  PROTOCOL_VERSION,
  type DeviceInput,
  type MutationResult,
  type SyncItem,
  type SyncMutation,
  type SyncResponse,
} from './protocol';
import { DEVICE_HEADER, REQUEST_HEADER, verifySignedRequest } from './signatures';
import { parseBootstrap, parseEnvelope, parseId, parsePairingApprove, parsePairingCreate, parseSync } from './validation';
import type { RuntimeEnv } from './env';
import { assertCursor, changeFits, decideMutation, jsonByteLength } from './sync-engine';

type Sql = DurableObjectState['storage']['sql'];

interface MetaRow {
  current_revision: number;
  created_at: string;
  vault_id: string | null;
  server_id: string;
  bootstrap_completed_at: string | null;
}

interface DeviceRow {
  device_id: string;
  auth_algorithm: string;
  auth_public_key: ArrayBuffer;
  created_at: string;
  last_seen_at: string | null;
  last_cursor: number;
  revoked_at: string | null;
  metadata_ciphertext: ArrayBuffer | null;
}

interface ItemRow {
  item_id: string;
  revision: number;
  deleted: number;
  crypto_version: number | null;
  nonce: ArrayBuffer | null;
  ciphertext: ArrayBuffer | null;
}

interface PairingRow {
  pairing_id: string;
  polling_secret_hash: string;
  transfer_public_key: ArrayBuffer;
  device_id: string;
  auth_algorithm: string;
  auth_public_key: ArrayBuffer;
  metadata_ciphertext: ArrayBuffer | null;
  human_code: string;
  state: string;
  transfer_payload: ArrayBuffer | null;
  approval_digest: string | null;
  created_at: string;
  expires_at: string;
}

const jsonHeaders = { 'content-type': 'application/json; charset=utf-8' };
const nowIso = (): string => new Date().toISOString();
const bytes = (value: ArrayBuffer): Uint8Array<ArrayBuffer> => new Uint8Array(value);
const blob = (value: string, field: string): ArrayBuffer => base64ToBytes(value, field).buffer;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: jsonHeaders });
}

async function readJson(body: Uint8Array): Promise<unknown> {
  if (body.byteLength === 0) throw new ApiError('invalid_request', 'A JSON request body is required.', 400);
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new ApiError('invalid_request', 'Request body must be valid JSON.', 400);
  }
}

function itemFromRow(row: ItemRow): SyncItem {
  const item: SyncItem = { itemId: row.item_id, revision: row.revision, deleted: row.deleted === 1 };
  if (!item.deleted) {
    item.cryptoVersion = row.crypto_version as number;
    item.nonce = bytesToBase64(bytes(row.nonce as ArrayBuffer));
    item.ciphertext = bytesToBase64(bytes(row.ciphertext as ArrayBuffer));
  }
  return item;
}

function rows<T>(sql: Sql, statement: string, ...bindings: SqlStorageValue[]): T[] {
  return sql.exec(statement, ...bindings).toArray() as T[];
}

function getOne<T>(sql: Sql, statement: string, ...bindings: SqlStorageValue[]): T | null {
  return rows<T>(sql, statement, ...bindings)[0] ?? null;
}

export class VaultDurableObject extends DurableObject<RuntimeEnv> {
  private readonly sql: Sql;
  private readonly limits: Limits;

  constructor(ctx: DurableObjectState, env: RuntimeEnv) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.limits = getLimits(env);
    ctx.blockConcurrencyWhile(async () => ctx.storage.transactionSync(() => this.migrate()));
  }

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS vault_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        protocol_version INTEGER NOT NULL,
        current_revision INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        vault_id TEXT,
        server_id TEXT NOT NULL,
        bootstrap_completed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        auth_algorithm TEXT NOT NULL,
        auth_public_key BLOB NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT,
        last_cursor INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT,
        metadata_ciphertext BLOB
      );
      CREATE TABLE IF NOT EXISTS sync_items (
        item_id TEXT PRIMARY KEY,
        revision INTEGER NOT NULL UNIQUE,
        deleted INTEGER NOT NULL,
        crypto_version INTEGER,
        nonce BLOB,
        ciphertext BLOB,
        CHECK ((deleted = 1 AND crypto_version IS NULL AND nonce IS NULL AND ciphertext IS NULL)
          OR (deleted = 0 AND crypto_version IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS idx_sync_items_revision ON sync_items(revision);
      CREATE TABLE IF NOT EXISTS key_envelopes (
        envelope_id TEXT PRIMARY KEY,
        envelope_type TEXT NOT NULL,
        credential_ref TEXT,
        crypto_version INTEGER NOT NULL,
        nonce BLOB,
        ciphertext BLOB NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sync_request_results (
        device_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        response_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(device_id, request_id)
      );
      CREATE INDEX IF NOT EXISTS idx_sync_results_created ON sync_request_results(device_id, created_at DESC);
      CREATE TABLE IF NOT EXISTS pairings (
        pairing_id TEXT PRIMARY KEY,
        polling_secret_hash TEXT NOT NULL,
        transfer_public_key BLOB NOT NULL,
        device_id TEXT NOT NULL,
        auth_algorithm TEXT NOT NULL,
        auth_public_key BLOB NOT NULL,
        metadata_ciphertext BLOB,
        human_code TEXT NOT NULL,
        state TEXT NOT NULL,
        transfer_payload BLOB,
        approval_digest TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_pairings_state_expiry ON pairings(state, expires_at);
      CREATE TABLE IF NOT EXISTS pairing_rate_limits (
        source_hash TEXT NOT NULL,
        bucket_start INTEGER NOT NULL,
        request_count INTEGER NOT NULL,
        PRIMARY KEY(source_hash, bucket_start)
      );
      INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, datetime('now'));
    `);
    const meta = getOne<MetaRow>(this.sql, 'SELECT * FROM vault_meta WHERE singleton = 1');
    if (!meta) {
      this.sql.exec(
        'INSERT INTO vault_meta(singleton, protocol_version, current_revision, created_at, vault_id, server_id, bootstrap_completed_at) VALUES (1, ?, 0, ?, NULL, ?, NULL)',
        PROTOCOL_VERSION,
        nowIso(),
        crypto.randomUUID(),
      );
    }
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const body = new Uint8Array(await request.arrayBuffer());
      if (request.method === 'GET' && url.pathname === '/v1/info') return this.info();
      if (request.method === 'POST' && url.pathname === '/v1/bootstrap/device') return await this.bootstrap(request, body);
      if (request.method === 'POST' && url.pathname === '/v1/pairings') return await this.createPairing(request, body);
      const pairingMatch = url.pathname.match(/^\/v1\/pairings\/([^/]+)$/);
      const consumeMatch = url.pathname.match(/^\/v1\/pairings\/([^/]+)\/consume$/);
      if (pairingMatch && pairingMatch[1] !== 'pending' && request.method === 'GET') return await this.pollPairing(request, parseId(pairingMatch[1] as string, 'pairingId'));
      if (consumeMatch && request.method === 'POST') return await this.consumePairing(request, parseId(consumeMatch[1] as string, 'pairingId'));

      const device = await this.authenticate(request, body);
      if (request.method === 'POST' && url.pathname === '/v1/sync') return await this.sync(device, body);
      if (request.method === 'GET' && url.pathname === '/v1/devices') return this.listDevices(device.device_id);
      const deviceMatch = url.pathname.match(/^\/v1\/devices\/([^/]+)$/);
      if (deviceMatch && request.method === 'DELETE') return this.revokeDevice(device.device_id, parseId(deviceMatch[1] as string, 'deviceId'));
      if (request.method === 'GET' && url.pathname === '/v1/envelopes') return this.listEnvelopes(device.device_id);
      const envelopeMatch = url.pathname.match(/^\/v1\/envelopes\/([^/]+)$/);
      if (envelopeMatch && request.method === 'PUT') return await this.putEnvelope(device.device_id, parseId(envelopeMatch[1] as string, 'envelopeId'), body);
      if (envelopeMatch && request.method === 'DELETE') return this.deleteEnvelope(device.device_id, parseId(envelopeMatch[1] as string, 'envelopeId'));
      if (request.method === 'GET' && url.pathname === '/v1/pairings/pending') return this.listPendingPairings(device.device_id);
      const approveMatch = url.pathname.match(/^\/v1\/pairings\/([^/]+)\/approve$/);
      if (approveMatch && request.method === 'POST') return await this.approvePairing(device.device_id, parseId(approveMatch[1] as string, 'pairingId'), body);
      throw new ApiError('not_found', 'Endpoint not found.', 404);
    } catch (error) {
      if (error instanceof ApiError) return errorResponse(error);
      if (error instanceof Error && (error.message.includes('SQLITE_FULL') || error.message.includes('database or disk is full'))) {
        return errorResponse(new ApiError('internal_error', 'Vault storage capacity has been reached.', 507));
      }
      console.error(JSON.stringify({ event: 'vault_error', code: 'internal_error' }));
      return errorResponse(new ApiError('internal_error', 'An internal error occurred.', 500));
    }
  }

  private meta(): MetaRow {
    return getOne<MetaRow>(this.sql, 'SELECT * FROM vault_meta WHERE singleton = 1') as MetaRow;
  }

  private assertSetup(): MetaRow {
    const meta = this.meta();
    if (!meta.bootstrap_completed_at) throw new ApiError('setup_required', 'The vault has not been bootstrapped.', 409);
    return meta;
  }

  private info(): Response {
    const meta = this.meta();
    return json({
      protocolVersions: [PROTOCOL_VERSION],
      serverId: meta.server_id,
      mode: 'single-user',
      setupRequired: !meta.bootstrap_completed_at,
      vaultHandle: meta.bootstrap_completed_at ? this.ctx.id.toString() : undefined,
      capabilities: ['device-signatures', 'pairing', 'key-envelopes', 'terminal-tombstones'],
      limits: {
        maxRequestBytes: this.limits.maxRequestBytes,
        maxItemBytes: this.limits.maxItemBytes,
        maxMutationsPerSync: this.limits.maxMutationsPerSync,
        maxResponseItems: this.limits.maxResponseItems,
        maxResponseBytes: this.limits.maxResponseBytes,
      },
    });
  }

  private async bootstrap(request: Request, body: Uint8Array): Promise<Response> {
    const existing = this.meta();
    if (existing.bootstrap_completed_at) throw new ApiError('setup_already_completed', 'The one-time bootstrap has already completed.', 409);
    const authorization = request.headers.get('authorization');
    const supplied = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!this.env.SETUP_TOKEN || !supplied || !constantTimeEqual(supplied, this.env.SETUP_TOKEN)) {
      throw new ApiError('unauthorized', 'The setup token is invalid.', 401);
    }
    const input = parseBootstrap(await readJson(body), this.limits);
    await this.validateDevicePublicKey(input.device);
    const timestamp = nowIso();
    this.ctx.storage.transactionSync(() => {
      const current = this.meta();
      if (current.bootstrap_completed_at) throw new ApiError('setup_already_completed', 'The one-time bootstrap has already completed.', 409);
      this.insertDevice(input.device, timestamp);
      this.sql.exec('UPDATE vault_meta SET vault_id = ?, bootstrap_completed_at = ? WHERE singleton = 1', input.vaultId, timestamp);
    });
    return json({ protocolVersion: PROTOCOL_VERSION, vaultId: input.vaultId, vaultHandle: this.ctx.id.toString(), deviceId: input.device.deviceId }, 201);
  }

  private insertDevice(device: DeviceInput, timestamp: string): void {
    this.sql.exec(
      'INSERT INTO devices(device_id, auth_algorithm, auth_public_key, created_at, last_seen_at, last_cursor, revoked_at, metadata_ciphertext) VALUES (?, ?, ?, ?, ?, 0, NULL, ?)',
      device.deviceId,
      device.authAlgorithm,
      blob(device.authPublicKey, 'authPublicKey'),
      timestamp,
      timestamp,
      device.metadataCiphertext ? blob(device.metadataCiphertext, 'metadataCiphertext') : null,
    );
  }

  private async validateDevicePublicKey(device: DeviceInput): Promise<void> {
    try {
      await crypto.subtle.importKey('spki', blob(device.authPublicKey, 'authPublicKey'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    } catch {
      throw new ApiError('invalid_request', 'Device authPublicKey must be a valid ECDSA P-256 SPKI key.', 400);
    }
  }

  private async authenticate(request: Request, body: Uint8Array): Promise<DeviceRow> {
    this.assertSetup();
    const rawDeviceId = request.headers.get(DEVICE_HEADER);
    if (!rawDeviceId) throw new ApiError('unauthorized', 'Missing device identifier.', 401);
    const deviceId = parseId(rawDeviceId, 'deviceId');
    const requestId = request.headers.get(REQUEST_HEADER);
    if (!requestId) throw new ApiError('unauthorized', 'Missing signed request identifier.', 401);
    parseId(requestId, 'requestId');
    const device = getOne<DeviceRow>(this.sql, 'SELECT * FROM devices WHERE device_id = ?', deviceId);
    if (!device) throw new ApiError('unauthorized', 'Unknown device.', 401);
    if (device.revoked_at) throw new ApiError('device_revoked', 'The device has been revoked.', 401);
    if (device.auth_algorithm !== AUTH_ALGORITHM) throw new ApiError('unauthorized', 'Unsupported stored device algorithm.', 401);
    await verifySignedRequest(request, body, bytes(device.auth_public_key), device.device_id, this.limits.signatureWindowSeconds);
    const current = getOne<DeviceRow>(this.sql, 'SELECT * FROM devices WHERE device_id = ?', deviceId);
    if (!current || current.revoked_at) throw new ApiError('device_revoked', 'The device has been revoked.', 401);
    return current;
  }

  private async sync(device: DeviceRow, body: Uint8Array): Promise<Response> {
    const input = parseSync(await readJson(body), this.limits);
    const digest = await sha256Base64(body);
    const responseJson = this.ctx.storage.transactionSync(() => {
      const stored = getOne<{ request_digest: string; response_json: string }>(
        this.sql,
        'SELECT request_digest, response_json FROM sync_request_results WHERE device_id = ? AND request_id = ?',
        device.device_id,
        input.syncRequestId,
      );
      if (stored) {
        if (stored.request_digest !== digest) throw new ApiError('request_id_reused', 'syncRequestId was reused with a different body.', 409);
        return stored.response_json;
      }

      let revision = this.meta().current_revision;
      assertCursor(input.cursor, revision);
      const mutationResults: MutationResult[] = [];
      for (const mutation of input.mutations) {
        const current = getOne<ItemRow>(this.sql, 'SELECT * FROM sync_items WHERE item_id = ?', mutation.itemId);
        const decision = decideMutation(current ? { revision: current.revision, deleted: current.deleted === 1 } : null, mutation);
        if (!decision.apply) {
          const result: MutationResult = {
            itemId: mutation.itemId,
            status: 'conflict',
            current: current ? itemFromRow(current) : null,
          };
          if (decision.code) result.code = decision.code;
          mutationResults.push(result);
          continue;
        }
        revision += 1;
        this.writeMutation(mutation, revision);
        mutationResults.push({ itemId: mutation.itemId, status: 'ok', revision });
      }
      if (revision !== this.meta().current_revision) this.sql.exec('UPDATE vault_meta SET current_revision = ? WHERE singleton = 1', revision);

      const base: SyncResponse = {
        protocolVersion: PROTOCOL_VERSION,
        serverRevision: revision,
        nextCursor: input.cursor,
        hasMore: false,
        mutationResults,
        changes: [],
      };
      if (jsonByteLength(base) > this.limits.maxResponseBytes) {
        throw new ApiError('response_too_large', 'Conflict results exceed maxResponseBytes; retry with a smaller mutation batch.', 413);
      }
      const cursor = this.sql.exec('SELECT * FROM sync_items WHERE revision > ? ORDER BY revision', input.cursor) as unknown as Iterable<ItemRow>;
      for (const row of cursor) {
        if (base.changes.length >= (input.limit as number)) break;
        const candidate = itemFromRow(row);
        if (!changeFits(base, candidate, this.limits.maxResponseBytes)) break;
        base.changes.push(candidate);
        base.nextCursor = candidate.revision;
      }
      base.hasMore = getOne<{ present: number }>(this.sql, 'SELECT 1 AS present FROM sync_items WHERE revision > ? LIMIT 1', base.nextCursor) !== null;
      const serialized = JSON.stringify(base);
      if (new TextEncoder().encode(serialized).byteLength > this.limits.maxResponseBytes) throw new ApiError('response_too_large', 'Sync response exceeds maxResponseBytes.', 413);
      const timestamp = nowIso();
      this.sql.exec('UPDATE devices SET last_seen_at = ?, last_cursor = MAX(last_cursor, ?) WHERE device_id = ?', timestamp, base.nextCursor, device.device_id);
      this.sql.exec(
        'INSERT INTO sync_request_results(device_id, request_id, request_digest, response_json, created_at) VALUES (?, ?, ?, ?, ?)',
        device.device_id,
        input.syncRequestId,
        digest,
        serialized,
        timestamp,
      );
      this.gcSyncResults(device.device_id, timestamp);
      return serialized;
    });
    return new Response(responseJson, { headers: jsonHeaders });
  }

  private writeMutation(mutation: SyncMutation, revision: number): void {
    const values = mutation.deleted
      ? [mutation.itemId, revision, 1, null, null, null]
      : [mutation.itemId, revision, 0, mutation.cryptoVersion, blob(mutation.nonce as string, 'nonce'), blob(mutation.ciphertext as string, 'ciphertext')];
    this.sql.exec(
      `INSERT INTO sync_items(item_id, revision, deleted, crypto_version, nonce, ciphertext)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(item_id) DO UPDATE SET revision = excluded.revision, deleted = excluded.deleted,
         crypto_version = excluded.crypto_version, nonce = excluded.nonce, ciphertext = excluded.ciphertext`,
      ...values,
    );
  }

  private gcSyncResults(deviceId: string, timestamp: string): void {
    const cutoff = new Date(Date.parse(timestamp) - 24 * 60 * 60 * 1000).toISOString();
    this.sql.exec('DELETE FROM sync_request_results WHERE device_id = ? AND created_at < ?', deviceId, cutoff);
    this.sql.exec(
      `DELETE FROM sync_request_results WHERE device_id = ? AND request_id IN (
        SELECT request_id FROM sync_request_results WHERE device_id = ? ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 64
      )`,
      deviceId,
      deviceId,
    );
  }

  private touch(deviceId: string): void {
    this.sql.exec('UPDATE devices SET last_seen_at = ? WHERE device_id = ?', nowIso(), deviceId);
  }

  private listDevices(deviceId: string): Response {
    this.touch(deviceId);
    const devices = rows<DeviceRow>(this.sql, 'SELECT * FROM devices ORDER BY created_at').map((row) => ({
      deviceId: row.device_id,
      authAlgorithm: row.auth_algorithm,
      authPublicKey: bytesToBase64(bytes(row.auth_public_key)),
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
      lastCursor: row.last_cursor,
      revokedAt: row.revoked_at,
      metadataCiphertext: row.metadata_ciphertext ? bytesToBase64(bytes(row.metadata_ciphertext)) : null,
    }));
    return json({ devices });
  }

  private revokeDevice(actorId: string, targetId: string): Response {
    this.ctx.storage.transactionSync(() => {
      const target = getOne<DeviceRow>(this.sql, 'SELECT * FROM devices WHERE device_id = ?', targetId);
      if (!target) return;
      if (target.revoked_at) return;
      const active = getOne<{ count: number }>(this.sql, 'SELECT COUNT(*) AS count FROM devices WHERE revoked_at IS NULL')?.count ?? 0;
      if (active <= 1) throw new ApiError('last_active_device', 'The final active device cannot be revoked.', 409);
      this.sql.exec('UPDATE devices SET revoked_at = ? WHERE device_id = ?', nowIso(), targetId);
      this.touch(actorId);
    });
    return new Response(null, { status: 204 });
  }

  private listEnvelopes(deviceId: string): Response {
    this.touch(deviceId);
    const envelopes = rows<{
      envelope_id: string; envelope_type: string; credential_ref: string | null; crypto_version: number;
      nonce: ArrayBuffer | null; ciphertext: ArrayBuffer; created_at: string; updated_at: string;
    }>(this.sql, 'SELECT * FROM key_envelopes ORDER BY created_at').map((row) => ({
      envelopeId: row.envelope_id,
      type: row.envelope_type,
      credentialRef: row.credential_ref,
      cryptoVersion: row.crypto_version,
      nonce: row.nonce ? bytesToBase64(bytes(row.nonce)) : null,
      ciphertext: bytesToBase64(bytes(row.ciphertext)),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
    return json({ envelopes });
  }

  private async putEnvelope(deviceId: string, envelopeId: string, body: Uint8Array): Promise<Response> {
    const input = parseEnvelope(await readJson(body), this.limits);
    const timestamp = nowIso();
    this.sql.exec(
      `INSERT INTO key_envelopes(envelope_id, envelope_type, credential_ref, crypto_version, nonce, ciphertext, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(envelope_id) DO UPDATE SET envelope_type = excluded.envelope_type, credential_ref = excluded.credential_ref,
         crypto_version = excluded.crypto_version, nonce = excluded.nonce, ciphertext = excluded.ciphertext, updated_at = excluded.updated_at`,
      envelopeId,
      input.type,
      input.credentialRef ?? null,
      input.cryptoVersion,
      input.nonce ? blob(input.nonce, 'nonce') : null,
      blob(input.ciphertext, 'ciphertext'),
      timestamp,
      timestamp,
    );
    this.touch(deviceId);
    return json({ envelopeId, updatedAt: timestamp });
  }

  private deleteEnvelope(deviceId: string, envelopeId: string): Response {
    this.sql.exec('DELETE FROM key_envelopes WHERE envelope_id = ?', envelopeId);
    this.touch(deviceId);
    return new Response(null, { status: 204 });
  }

  private expirePairings(): void {
    this.sql.exec(
      `UPDATE pairings SET state = 'cancelled', transfer_payload = NULL
       WHERE state IN ('pending', 'approved') AND expires_at <= ?`,
      nowIso(),
    );
  }

  private async createPairing(request: Request, body: Uint8Array): Promise<Response> {
    this.assertSetup();
    const input = parsePairingCreate(await readJson(body), this.limits);
    await this.validateDevicePublicKey(input.device);
    const source = request.headers.get('x-supatabs-internal-source') || 'local';
    const now = Date.now();
    const bucket = Math.floor(now / (this.limits.pairingRateWindowSeconds * 1000));
    this.ctx.storage.transactionSync(() => {
      this.expirePairings();
      this.sql.exec('DELETE FROM pairing_rate_limits WHERE bucket_start < ?', bucket - 1);
      const existing = getOne<{ request_count: number }>(this.sql, 'SELECT request_count FROM pairing_rate_limits WHERE source_hash = ? AND bucket_start = ?', source, bucket);
      if ((existing?.request_count ?? 0) >= this.limits.pairingRateLimit) throw new ApiError('rate_limited', 'Too many pairing requests.', 429);
      this.sql.exec(
        `INSERT INTO pairing_rate_limits(source_hash, bucket_start, request_count) VALUES (?, ?, 1)
         ON CONFLICT(source_hash, bucket_start) DO UPDATE SET request_count = request_count + 1`,
        source,
        bucket,
      );
    });
    const secretBytes = crypto.getRandomValues(new Uint8Array(32));
    const pollingSecret = bytesToBase64Url(secretBytes);
    const pairingId = crypto.randomUUID();
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + this.limits.pairingTtlSeconds * 1000).toISOString();
    let humanCode = '';
    let codeAvailable = false;
    for (let attempt = 0; attempt < 10; attempt++) {
      humanCode = String(crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).padStart(6, '0');
      if (!getOne(this.sql, `SELECT 1 FROM pairings WHERE human_code = ? AND state IN ('pending', 'approved') AND expires_at > ?`, humanCode, createdAt)) {
        codeAvailable = true;
        break;
      }
    }
    if (!codeAvailable) throw new ApiError('internal_error', 'Unable to allocate a pairing code.', 503);
    this.sql.exec(
      `INSERT INTO pairings(pairing_id, polling_secret_hash, transfer_public_key, device_id, auth_algorithm, auth_public_key,
       metadata_ciphertext, human_code, state, transfer_payload, approval_digest, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)`,
      pairingId,
      await sha256Base64Url(utf8(pollingSecret)),
      blob(input.transferPublicKey, 'transferPublicKey'),
      input.device.deviceId,
      input.device.authAlgorithm,
      blob(input.device.authPublicKey, 'authPublicKey'),
      input.device.metadataCiphertext ? blob(input.device.metadataCiphertext, 'metadataCiphertext') : null,
      humanCode,
      createdAt,
      expiresAt,
    );
    return json({ pairingId, pollingSecret, humanCode, expiresAt }, 201);
  }

  private listPendingPairings(deviceId: string): Response {
    this.expirePairings();
    this.touch(deviceId);
    const pairings = rows<PairingRow>(this.sql, `SELECT * FROM pairings WHERE state = 'pending' AND expires_at > ? ORDER BY created_at`, nowIso()).map((row) => ({
      pairingId: row.pairing_id,
      humanCode: row.human_code,
      device: {
        deviceId: row.device_id,
        authAlgorithm: row.auth_algorithm,
        authPublicKey: bytesToBase64(bytes(row.auth_public_key)),
        metadataCiphertext: row.metadata_ciphertext ? bytesToBase64(bytes(row.metadata_ciphertext)) : null,
      },
      transferPublicKey: bytesToBase64(bytes(row.transfer_public_key)),
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    }));
    return json({ pairings });
  }

  private async approvePairing(actorId: string, pairingId: string, body: Uint8Array): Promise<Response> {
    const input = parsePairingApprove(await readJson(body), this.limits);
    const digest = await sha256Base64(body);
    const result = this.ctx.storage.transactionSync(() => {
      this.expirePairings();
      const pairing = getOne<PairingRow>(this.sql, 'SELECT * FROM pairings WHERE pairing_id = ?', pairingId);
      if (!pairing) throw new ApiError('not_found', 'Pairing not found.', 404);
      if ((pairing.state === 'approved' || pairing.state === 'consumed') && pairing.approval_digest === digest) {
        return { pairingId, state: pairing.state };
      }
      if (pairing.state !== 'pending') throw new ApiError('invalid_pairing_state', `Pairing is ${pairing.state}.`, 409);
      if (getOne(this.sql, 'SELECT 1 FROM devices WHERE device_id = ?', pairing.device_id)) throw new ApiError('invalid_pairing_state', 'The proposed device ID already exists.', 409);
      this.sql.exec(
        'INSERT INTO devices(device_id, auth_algorithm, auth_public_key, created_at, last_seen_at, last_cursor, revoked_at, metadata_ciphertext) VALUES (?, ?, ?, ?, NULL, 0, NULL, ?)',
        pairing.device_id,
        pairing.auth_algorithm,
        pairing.auth_public_key,
        nowIso(),
        pairing.metadata_ciphertext,
      );
      this.sql.exec(`UPDATE pairings SET state = 'approved', transfer_payload = ?, approval_digest = ? WHERE pairing_id = ?`, blob(input.transferPayload, 'transferPayload'), digest, pairingId);
      this.touch(actorId);
      return { pairingId, state: 'approved' };
    });
    return json(result);
  }

  private pairingSecret(request: Request): string {
    const authorization = request.headers.get('authorization');
    if (!authorization?.startsWith('SupaTabs-Pairing ')) throw new ApiError('unauthorized', 'Missing pairing authorization.', 401);
    const secret = authorization.slice('SupaTabs-Pairing '.length);
    if (secret.length < 32 || secret.length > 128) throw new ApiError('unauthorized', 'Invalid pairing authorization.', 401);
    return secret;
  }

  private async authorizedPairing(request: Request, pairingId: string): Promise<PairingRow> {
    this.expirePairings();
    const pairing = getOne<PairingRow>(this.sql, 'SELECT * FROM pairings WHERE pairing_id = ?', pairingId);
    if (!pairing) throw new ApiError('not_found', 'Pairing not found.', 404);
    const suppliedHash = await sha256Base64Url(utf8(this.pairingSecret(request)));
    if (!constantTimeEqual(suppliedHash, pairing.polling_secret_hash)) throw new ApiError('unauthorized', 'Invalid pairing secret.', 401);
    return pairing;
  }

  private async pollPairing(request: Request, pairingId: string): Promise<Response> {
    const pairing = await this.authorizedPairing(request, pairingId);
    return json({
      pairingId,
      state: pairing.state,
      expiresAt: pairing.expires_at,
      vaultHandle: pairing.state === 'approved' ? this.ctx.id.toString() : undefined,
      transferPayload: pairing.state === 'approved' && pairing.transfer_payload ? bytesToBase64(bytes(pairing.transfer_payload)) : undefined,
    });
  }

  private async consumePairing(request: Request, pairingId: string): Promise<Response> {
    const pairing = await this.authorizedPairing(request, pairingId);
    if (pairing.state === 'consumed') return new Response(null, { status: 204 });
    if (pairing.state !== 'approved') throw new ApiError('invalid_pairing_state', `Pairing is ${pairing.state}.`, 409);
    this.sql.exec(`UPDATE pairings SET state = 'consumed', transfer_payload = NULL WHERE pairing_id = ?`, pairingId);
    return new Response(null, { status: 204 });
  }
}
