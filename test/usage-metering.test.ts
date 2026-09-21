import { describe, expect, it } from 'vitest';
import {
  createUsageMetrics,
  instrumentSql,
  routeTemplate,
  usageDataPoint,
  usageStorage,
  writeUsageDataPoint,
} from '../src/usage-metering';

describe('usage metering', () => {
  it('produces the stable per-vault Analytics Engine schema', () => {
    const metrics = createUsageMetrics();
    metrics.requestBytes = 120;
    metrics.responseBytes = 240;
    metrics.durationMs = 12.5;
    metrics.status = 409;
    metrics.errorCode = 'request_id_reused';
    metrics.entitlementTier = 'pro';
    metrics.accessMode = 'read_write';
    metrics.mutationsSubmitted = 3;
    metrics.mutationsApplied = 1;
    metrics.mutationsConflicted = 2;
    metrics.changesReturned = 4;
    metrics.idempotentRetry = 1;
    metrics.cursors.push({ rowsRead: 7, rowsWritten: 8 });
    metrics.cursors.push({ rowsRead: 2, rowsWritten: 1 });

    expect(usageDataPoint({
      vaultHandle: 'a'.repeat(64),
      routeTemplate: '/v1/sync',
      method: 'POST',
      metrics,
      databaseSizeBytes: 4096,
    })).toEqual({
      indexes: ['a'.repeat(64)],
      blobs: ['1', '/v1/sync', 'POST', '409', 'request_id_reused', 'pro', 'read_write'],
      doubles: [1, 120, 240, 12.5, 9, 9, 4096, 3, 1, 2, 4, 1],
    });
  });

  it('does not put untemplated path identifiers into analytics dimensions', () => {
    expect(routeTemplate('/v1/devices/device-secret')).toBe('/v1/devices/:deviceId');
    expect(routeTemplate('/v1/not-an-endpoint/secret')).toBe('/v1/:unknown');
    expect(usageDataPoint({
      vaultHandle: 'b'.repeat(64),
      routeTemplate: '/v1/not-an-endpoint/secret',
      method: 'TRACE\nsecret',
      metrics: createUsageMetrics(),
      databaseSizeBytes: Number.NaN,
    })).toMatchObject({
      blobs: ['1', '/v1/:unknown', 'UNKNOWN', '500', '', '', ''],
      doubles: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    });
  });

  it('tracks SQL cursor rows in the request-local context', () => {
    const cursor = { rowsRead: 4, rowsWritten: 2 };
    const sql = {
      exec: (_query: string) => cursor,
      get databaseSize() { return 64; },
    };
    const metrics = createUsageMetrics();
    const instrumented = instrumentSql(sql);
    const result = usageStorage.run(metrics, () => instrumented.exec('SELECT 1'));
    expect(result).toBe(cursor);
    expect(metrics.cursors).toEqual([cursor]);
    expect(instrumented.databaseSize).toBe(64);
  });

  it('never lets Analytics Engine failures affect the request', () => {
    const calls: unknown[] = [];
    writeUsageDataPoint({
      writeDataPoint(point) {
        calls.push(point);
        throw new Error('analytics unavailable');
      },
    }, {
      vaultHandle: 'c'.repeat(64),
      routeTemplate: '/v1/info',
      method: 'GET',
      metrics: createUsageMetrics(),
      databaseSizeBytes: 1,
    });
    expect(calls).toHaveLength(1);
  });
});
