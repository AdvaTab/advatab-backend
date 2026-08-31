import { ApiError } from './errors';
import type { SyncMutation, SyncResponse, SyncItem } from './protocol';

export interface CurrentItemState {
  revision: number;
  deleted: boolean;
}

export type MutationDecision =
  | { apply: true }
  | { apply: false; code?: 'tombstone_terminal' };

export function decideMutation(current: CurrentItemState | null, mutation: SyncMutation): MutationDecision {
  if (!current) return mutation.expectedRevision === 0 ? { apply: true } : { apply: false };
  if (current.deleted && !mutation.deleted) return { apply: false, code: 'tombstone_terminal' };
  return mutation.expectedRevision > 0 && current.revision === mutation.expectedRevision
    ? { apply: true }
    : { apply: false };
}

export function assertCursor(cursor: number, serverRevision: number): void {
  if (cursor > serverRevision) throw new ApiError('invalid_request', 'cursor cannot exceed serverRevision.', 400);
}

export function jsonByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

export function changeFits(response: SyncResponse, candidate: SyncItem, maxBytes: number): boolean {
  return jsonByteLength({ ...response, nextCursor: candidate.revision, changes: [...response.changes, candidate] }) <= maxBytes;
}

export function assertPageProgress(cursor: number, nextCursor: number, hasMore: boolean): void {
  if (hasMore && nextCursor === cursor) {
    throw new ApiError('response_too_large', 'The next synchronized item exceeds maxResponseBytes; retry with a smaller response limit.', 413);
  }
}
