export type ErrorCode =
  | 'invalid_request'
  | 'unsupported_protocol'
  | 'unauthorized'
  | 'device_revoked'
  | 'signature_expired'
  | 'request_id_reused'
  | 'vault_not_found'
  | 'setup_required'
  | 'setup_already_completed'
  | 'rate_limited'
  | 'payload_too_large'
  | 'response_too_large'
  | 'tombstone_terminal'
  | 'last_active_device'
  | 'invalid_pairing_state'
  | 'recovery_unavailable'
  | 'not_found'
  | 'internal_error';

export class ApiError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export function errorResponse(error: ApiError): Response {
  return Response.json(
    { error: { code: error.code, message: error.message } },
    { status: error.status, headers: { 'content-type': 'application/json; charset=utf-8' } },
  );
}

export const invalid = (message: string): never => {
  throw new ApiError('invalid_request', message, 400);
};
