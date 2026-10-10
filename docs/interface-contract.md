# EPHEMERE: Interface Contract (DRAFT v0.4)

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
{ "assetId": "uuid", "ownerId": "uuid", "cid": "bafk... or bafy... (CIDv1)",
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
  "decision": "allow|deny|n/a", "reason": "UPPER_CASE_CODE, max 40 chars, never free text",
  "prevHash": "<64 hex>", "leafHash": "<64 hex>" }
```
Rules (enforced and tested in `audit/`): `orgId`, `grantId`, `assetId` are lower-case UUIDv4 (or null for grant/asset). `prevHash` is the previous event's `leafHash` (64 zeros for the first). `leafHash` = SHA-256(0x00 || canonical JSON of the event without `leafHash`); canonical JSON = sorted keys, no spaces, ASCII.

### 1.7 Checkpoint (signed by the operator, Ed25519)
```json
{ "size": 42, "root": "<64 hex>", "ts": "ts", "sig": "<b64>" }
```
Users, auditors or a public page should **store checkpoints themselves**. Tamper-evidence only works if someone besides the operator holds an old checkpoint.

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
| `POST /user/requests/{id}/approve` | Approve; body carries kfrags: `{kfrags: ["<b64>"], threshold: {m,n}}`. **The middleware checks the user's session, then forwards the kfrags to `POST /proxy/policies`. The browser never calls the proxy directly.** |
| `POST /user/requests/{id}/deny` | Deny |
| `POST /user/grants/{grantId}/revoke` | Revoke: proxy deletes kfrags, status → `revoked` |
| `GET /user/audit` | The user's audit history with Merkle inclusion proofs |

**Internal (separate FastAPI apps, not exposed to browsers)**
| Method + path | Purpose |
|---|---|
| `POST /proxy/policies` | Middleware stores kfrags + `expiresAt` for a grant. The proxy verifies each kfrag's owner signature, **refuses a revoked grant id, and refuses any kfrag that was revoked before** (tested in `spikes/pre`). |
| `POST /proxy/reencrypt` | `{grantId, capsule}` → `{cfrags}` or `403` if revoked/expired |
| `DELETE /proxy/policies/{grantId}` | Delete kfrags (revocation) |
| `POST /audit/events` | Append event → `{seq, leafHash}` |
| `GET /audit/checkpoint` | Latest **signed** checkpoint |
| `GET /audit/proof/{seq}` | Inclusion proof for one event (size must match a trusted checkpoint) |
| `GET /audit/consistency?oldSize=N` | Proof that the log extends an older checkpoint without rewriting it |

## 3. Error format
```json
{ "error": { "code": "GRANT_REVOKED", "message": "human readable" } }
```
Codes: `UNAUTHENTICATED`, `FORBIDDEN`, `GRANT_REVOKED`, `GRANT_EXPIRED`, `PROOF_INVALID`, `SIGNALS_MISMATCH`, `NONCE_REUSED`, `NOT_FOUND`.

## 4. Open questions (decide this week)
1. How does FastAPI verify Groth16 proofs: Node subprocess calling snarkjs, or a Python verifier? (A + C)
2. Where are wrapped DEKs and metadata stored for the MVP: SQLite or Postgres? (C + D)
3. Does the browser upload to IPFS directly, or through the backend? **Proposal: through the backend** (browser sends ciphertext, backend talks to Kubo), because Kubo's API gives full control of the node and must never be exposed. The browser always recomputes the CID of what it fetches (tested in `spikes/ipfs`). (B + D)
4. Authentication for users and orgs: simple email+password with JWT for the MVP? (D + C)
5. **Partly answered:** kfrags are already signed by the owner's signing key and the proxy verifies them. Still open: how the middleware proves to the proxy that the upload came from a logged-in owner session (for example an internal API key plus the user's session id). (B + C)
