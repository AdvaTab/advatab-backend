# SupaTabs Sync v1 wire fixtures

This document is the small, checked-in contract fixture used by the sync backend
and the extension. It covers the Phase 2 open/BYO protocol only. Managed cloud
provisioning remains in `customer-management` and does not add fields to these
sync records.

## Canonical binary representation

Every binary field crossing the HTTP boundary is padded RFC 4648 standard
base64. The following values are intentionally short and deterministic:

| Bytes (hex) | Standard base64 | Base64url form (legacy/local only) |
| --- | --- | --- |
| `00` | `AA==` | `AA` |
| `0102` | `AQI=` | `AQI` |
| `010203` | `AQID` | `AQID` |
| `fffe` | `//4=` | `__4` |

New protocol requests MUST use the standard padded form. Local extension
wrappers and exports MAY read the legacy base64url form for backward
compatibility.

## Bootstrap and recovery enrollment

Both enrollment operations use an ECDSA P-256 public key encoded as SPKI DER
and then standard base64. The exact key bytes are supplied by the test vector
implementation; the example below documents the shape rather than a usable
credential.

```http
POST /v1/bootstrap/device
Authorization: Bearer setup-token
Content-Type: application/json
```

```json
{
  "protocolVersion": 1,
  "vaultId": "vault-portable-01",
  "device": {
    "deviceId": "device-first",
    "authAlgorithm": "ecdsa-p256-sha256",
    "authPublicKey": "base64-SPKI-DER",
    "metadataCiphertext": null
  }
}
```

```json
{
  "protocolVersion": 1,
  "vaultId": "vault-portable-01",
  "vaultHandle": "backend-do-handle",
  "deviceId": "device-first"
}
```

The first response has status `201`. Repeating the same vault ID and device
SPKI after a lost response has status `200` and returns the same response
shape. A different vault ID, device ID, or public key returns
`setup_already_completed`.

Recovery enrollment is separate and never receives the recovery secret or
AccountKey:

```http
POST /v1/recovery/device
Authorization: Bearer recovery-enrollment-token
Content-Type: application/json
```

The JSON body is the same as bootstrap. A successful response is the same
canonical `{ protocolVersion, vaultId, vaultHandle, deviceId }` object.

## HTTP signature fixture

For a non-empty body, the covered component order is exactly:

```text
"@method" "@path" "@query" "content-digest"
"x-supatabs-device-id" "x-supatabs-vault-handle" "x-supatabs-request-id"
```

For an empty body, omit `content-digest`. For:

```text
POST https://sync.example.test/v1/sync?mode=full
Body bytes (hex): 010203
X-SupaTabs-Device-Id: device-first
X-SupaTabs-Vault-Handle: backend-do-handle
X-SupaTabs-Request-Id: request-01
Content-Digest: sha-256=:AQID:
```

the signature parameters are:

```text
("@method" "@path" "@query" "content-digest" "x-supatabs-device-id" "x-supatabs-vault-handle" "x-supatabs-request-id");created=1700000000;expires=1700000300;keyid="device-first";alg="ecdsa-p256-sha256"
```

and the canonical signature base is:

```text
"@method": post
"@path": /v1/sync
"@query": ?mode=full
"content-digest": sha-256=:AQID:
"x-supatabs-device-id": device-first
"x-supatabs-vault-handle": backend-do-handle
"x-supatabs-request-id": request-01
"@signature-params": ("@method" "@path" "@query" "content-digest" "x-supatabs-device-id" "x-supatabs-vault-handle" "x-supatabs-request-id");created=1700000000;expires=1700000300;keyid="device-first";alg="ecdsa-p256-sha256"
```

The ECDSA signature itself is standard padded base64 inside
`Signature: sig1=:<base64>:`.

## Pairing

Creation uses a nested device and opaque transfer public key:

```json
{
  "protocolVersion": 1,
  "transferPublicKey": "AQI=",
  "device": {
    "deviceId": "device-second",
    "authAlgorithm": "ecdsa-p256-sha256",
    "authPublicKey": "base64-SPKI-DER",
    "metadataCiphertext": null
  }
}
```

Approval uses one standard-base64 opaque serialized transfer payload:

```json
{ "transferPayload": "eyJmb3JtYXRWZXJzaW9uIjoxfQ==" }
```

Polling and consumption send the secret only as
`Authorization: SupaTabs-Pairing <polling-secret>`. The approved response
contains `transferPayload`; `POST /v1/pairings/{id}/consume` is sent only after
the extension has decrypted and installed it.

## Null conflict and pagination

An expected non-zero revision for an item that no longer exists is represented
without inventing an encrypted item:

```json
{
  "itemId": "item-01",
  "status": "conflict",
  "current": null
}
```

`hasMore: true` MUST always accompany a `nextCursor` greater than the request
cursor. A response that cannot include even the first pending change within
the configured response limit returns `response_too_large` instead of a page
that cannot make progress.
