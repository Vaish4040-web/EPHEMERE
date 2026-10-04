# EPHEMERE: Interface Contract (DRAFT v0.1)

Status: **proposal for the team to review and freeze in week 1.** Change it only via PR, and update the version number.

Conventions
- All binary values are **base64 (standard, padded)** strings of the library's own serialized bytes (umbral-pre capsule, kfrag, cfrag, public key). Do not invent encodings.
- Timestamps: ISO-8601 UTC strings. Dates of birth: **days since 1970-01-01** (integer).
- IDs: UUIDv4 strings.
- JSON field names are `camelCase`.
- Personal data (dob, names, file contents) **never** appears in audit events or logs.

## 1. Data objects

### 1.1 Credential (issuer → user, stays in the browser)
```json
{ "dobDay": 11123, "salt": "<decimal string>",
  "sig": { "S": "<decimal>", "R8x": "<decimal>", "R8y": "<decimal>" },
  "issuerPub": { "Ax": "<decimal>", "Ay": "<decimal>" } }
```

### 1.2 Challenge (middleware → user, per request)
```json
{ "requestId": "uuid", "nonce": "<decimal string>", "cutoffDay": 11800,
  "issuerPub": { "Ax": "<decimal>", "Ay": "<decimal>" } }
```
`cutoffDay` = (today − 18 years) in days, computed **by the middleware**, never by the user.

### 1.3 ProofBundle (user → middleware)
```json
{ "requestId": "uuid", "proof": { "...snarkjs groth16 proof..." },
  "publicSignals": ["issuerAx", "issuerAy", "cutoffDay", "nonce"] }
```
Order of `publicSignals` is fixed. Verifier rejects unless the signals equal the Challenge values **and** the proof verifies.

### 1.4 EncryptedAsset (stored as metadata; ciphertext is on IPFS)
```json
{ "assetId": "uuid", "ownerId": "uuid", "cid": "Qm...",
  "iv": "<b64, 12 bytes>", "aesAlg": "AES-GCM-256",
  "wrappedDek": { "capsule": "<b64>", "ciphertext": "<b64>" },
  "ownerPub": "<b64 umbral public key>", "createdAt": "ts" }
```

### 1.5 Grant
```json
{ "grantId": "uuid", "assetId": "uuid", "orgId": "uuid",
  "purpose": "string", "notBefore": "ts", "expiresAt": "ts",
  "status": "pending|active|revoked|expired",
  "delegatePub": "<b64 access-service umbral public key>",
  "threshold": { "m": 1, "n": 1 } }
```

### 1.6 AuditEvent
```json
{ "seq": 42, "ts": "ts",
  "type": "REQUEST_CREATED|ZK_VERIFIED|ZK_FAILED|GRANT_APPROVED|ACCESS_ALLOWED|ACCESS_DENIED|REVOKED|EXPIRED|KEY_ROTATED|ERASED",
  "grantId": "uuid|null", "orgId": "uuid", "assetId": "uuid|null",
  "decision": "allow|deny|n/a", "reason": "string (code, not free text with personal data)",
  "prevHash": "<hex>", "leafHash": "<hex>" }
```

## 2. Endpoints (REST, JSON)

**Org-facing (Company portal → middleware)**
| Method + path | Purpose |
|---|---|
| `POST /org/requests` | Org asks for data/attribute: `{orgId, assetId?, attribute?, purpose, durationSec}` → `{requestId}` |
| `GET /org/requests/{id}` | Status: `pending|approved|denied|revoked|expired` |
| `POST /org/requests/{id}/access` | Org triggers the operation. Response contains **only the operation result**, never keys or the file. |

**User-facing (Vault → middleware)**
| Method + path | Purpose |
|---|---|
| `GET /user/requests` | Pending requests for this user, including the Challenge |
| `POST /user/requests/{id}/proof` | Submit ProofBundle (when an attribute proof is required) |
| `POST /user/requests/{id}/approve` | Approve; body carries kfrags: `{kfrags: ["<b64>"], threshold: {m,n}}` |
| `POST /user/requests/{id}/deny` | Deny |
| `POST /user/grants/{grantId}/revoke` | Revoke: proxy deletes kfrags, status → `revoked` |
| `GET /user/audit` | The user's audit history with Merkle inclusion proofs |

**Internal (separate FastAPI apps, not exposed to browsers)**
| Method + path | Purpose |
|---|---|
| `POST /proxy/policies` | Access service/middleware stores kfrags + `expiresAt` for a grant |
| `POST /proxy/reencrypt` | `{grantId, capsule}` → `{cfrags}` or `403` if revoked/expired |
| `DELETE /proxy/policies/{grantId}` | Delete kfrags (revocation) |
| `POST /audit/events` | Append event → `{seq, leafHash}` |
| `GET /audit/root` | Current Merkle root + size |
| `GET /audit/proof/{seq}` | Inclusion proof for one event |

## 3. Error format
```json
{ "error": { "code": "GRANT_REVOKED", "message": "human readable" } }
```
Codes: `UNAUTHENTICATED`, `FORBIDDEN`, `GRANT_REVOKED`, `GRANT_EXPIRED`, `PROOF_INVALID`, `SIGNALS_MISMATCH`, `NONCE_REUSED`, `NOT_FOUND`.

## 4. Open questions (decide this week)
1. How does FastAPI verify Groth16 proofs: Node subprocess calling snarkjs, or a Python verifier? (A + C)
2. Where are wrapped DEKs and metadata stored for the MVP: SQLite or Postgres? (C + D)
3. Does the browser upload to IPFS directly, or through the backend? (B + D)
4. Authentication for users and orgs: simple email+password with JWT for the MVP? (D + C)
5. Does the owner sign the kfrags in a way the proxy can check the grant was authorized by the owner? (B)
