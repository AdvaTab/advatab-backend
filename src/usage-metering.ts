import { AsyncLocalStorage } from 'node:async_hooks';

type SqlCursor = {
  readonly rowsRead: number;
  readonly rowsWritten: number;
};

export interface UsageRequestMetrics {
  readonly cursors: SqlCursor[];
  requestBytes: number;
  responseBytes: number;
  durationMs: number;
  status: number;
  errorCode: string;
  entitlementTier: string;
  accessMode: string;
  mutationsSubmitted: number;
  mutationsApplied: number;
  mutationsConflicted: number;
  changesReturned: number;
  idempotentRetry: number;
}

export const USAGE_SCHEMA_VERSION = '1';

export const usageStorage = new AsyncLocalStorage<UsageRequestMetrics>();

export function createUsageMetrics(): UsageRequestMetrics {
  return {
    cursors: [],
    requestBytes: 0,
    responseBytes: 0,
    durationMs: 0,
    status: 500,
    errorCode: '',
    entitlementTier: '',
    accessMode: '',
    mutationsSubmitted: 0,
    mutationsApplied: 0,
    mutationsConflicted: 0,
    changesReturned: 0,
    idempotentRetry: 0,
  };
}

export function recordMutationMetrics(values: Partial<Pick<UsageRequestMetrics,
  'mutationsSubmitted' | 'mutationsApplied' | 'mutationsConflicted' | 'changesReturned' | 'idempotentRetry'>>): void {
  const metrics = usageStorage.getStore();
  if (!metrics) return;
  Object.assign(metrics, values);
}

export function instrumentSql<Sql extends { exec: (query: string, ...bindings: SqlStorageValue[]) => unknown }>(sql: Sql): Sql {
  return new Proxy(sql, {
    get(target, property, _receiver) {
      if (property !== 'exec') {
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }
      return (...args: unknown[]) => {
        const cursor = Reflect.apply(target.exec, target, args);
        const metrics = usageStorage.getStore();
        if (metrics && isSqlCursor(cursor)) metrics.cursors.push(cursor);
        return cursor;
      };
    },
  });
}

function isSqlCursor(value: unknown): value is SqlCursor {
  return typeof value === 'object' && value !== null && 'rowsRead' in value && 'rowsWritten' in value;
}

function safeDimension(value: string, fallback = ''): string {
  return /^[a-z0-9_./:-]{0,96}$/i.test(value) ? value : fallback;
}

export interface UsageDataPointInput {
  vaultHandle: string;
  routeTemplate: string;
  method: string;
  metrics: UsageRequestMetrics;
  databaseSizeBytes: number;
}

export function usageDataPoint(input: UsageDataPointInput): {
  indexes: [string];
  blobs: [string, string, string, string, string, string, string];
  doubles: [number, number, number, number, number, number, number, number, number, number, number, number];
} {
  const metrics = input.metrics;
  let sqliteRowsRead = 0;
  let sqliteRowsWritten = 0;
  for (const cursor of metrics.cursors) {
    sqliteRowsRead += Number.isFinite(cursor.rowsRead) ? Math.max(0, cursor.rowsRead) : 0;
    sqliteRowsWritten += Number.isFinite(cursor.rowsWritten) ? Math.max(0, cursor.rowsWritten) : 0;
  }
  return {
    indexes: [input.vaultHandle],
    blobs: [
      USAGE_SCHEMA_VERSION,
      safeDimension(routeTemplate(input.routeTemplate), '/v1/:unknown'),
      safeDimension(input.method, 'UNKNOWN'),
      String(Number.isInteger(metrics.status) ? metrics.status : 500),
      safeDimension(metrics.errorCode),
      safeDimension(metrics.entitlementTier),
      safeDimension(metrics.accessMode),
    ],
    doubles: [
      1,
      finiteNonNegative(metrics.requestBytes),
      finiteNonNegative(metrics.responseBytes),
      finiteNonNegative(metrics.durationMs),
      finiteNonNegative(sqliteRowsRead),
      finiteNonNegative(sqliteRowsWritten),
      finiteNonNegative(input.databaseSizeBytes),
      finiteNonNegative(metrics.mutationsSubmitted),
      finiteNonNegative(metrics.mutationsApplied),
      finiteNonNegative(metrics.mutationsConflicted),
      finiteNonNegative(metrics.changesReturned),
      metrics.idempotentRetry === 1 ? 1 : 0,
    ],
  };
}

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) ? Math.max(0, value) : 0;
}

export function writeUsageDataPoint(
  dataset: AnalyticsEngineDataset | undefined,
  input: UsageDataPointInput,
): void {
  if (!dataset) return;
  try {
    dataset.writeDataPoint(usageDataPoint(input));
  } catch {
    // Metering must never change the data-plane response or availability.
  }
}

export function routeTemplate(pathname: string): string {
  if (pathname === '/v1/info') return pathname;
  if (pathname === '/v1/bootstrap/device') return pathname;
  if (pathname === '/v1/recovery/device') return pathname;
  if (pathname === '/v1/pairings') return pathname;
  if (pathname === '/v1/pairings/pending') return pathname;
  if (pathname === '/v1/sync') return pathname;
  if (pathname === '/v1/devices') return pathname;
  if (pathname === '/v1/envelopes') return pathname;
  if (/^\/v1\/devices\/[^/]+$/.test(pathname)) return '/v1/devices/:deviceId';
  if (/^\/v1\/envelopes\/[^/]+$/.test(pathname)) return '/v1/envelopes/:envelopeId';
  if (/^\/v1\/pairings\/[^/]+\/approve$/.test(pathname)) return '/v1/pairings/:pairingId/approve';
  if (/^\/v1\/pairings\/[^/]+\/consume$/.test(pathname)) return '/v1/pairings/:pairingId/consume';
  if (/^\/v1\/pairings\/[^/]+$/.test(pathname)) return '/v1/pairings/:pairingId';
  return pathname.startsWith('/v1/') ? '/v1/:unknown' : 'other';
}
