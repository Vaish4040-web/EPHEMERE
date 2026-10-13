# EPHEMERE: Interface Contract (DRAFT v0.6)

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
  "label": "profile.json (plain text, no personal details)", "sizeBytes": 171,
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

## 2a. Built so far (M1 and M2), in real use
**All browser-facing paths live under `/api`** (the web app passes `/api/...` on to the gateway). Paths listed in section 2 without that prefix will get it when they are built.

| Method + path | Who | What |
|---|---|---|
| `GET /api/status` | anyone | Honest status of every part (no secrets) |
| `POST /api/demo/login` | anyone | `{account: "asha"|"ravi"|"quickdeliver"}` -> `{token, account:{id, role, name}}`. **Demo only: no passwords.** Switch off with `DEMO_LOGIN=off`. |
| `POST /api/assets` | user | Upload an encrypted file: `{assetId, label, iv, capsule, wrappedDek, ownerPk, verifyingPk, ciphertext}` (all base64 except ids and label) -> `201 {assetId, cid, sizeBytes}` |
| `GET /api/assets` | user | The caller's own files: `{assets:[{assetId, label, cid, sizeBytes, createdAt}]}` |
| `GET /api/assets/{id}` | owner | Metadata plus the pieces needed to open the file (`iv, capsule, wrappedDek, ownerPk, verifyingPk`) |
| `GET /api/assets/{id}/ciphertext` | owner | The encrypted bytes (`application/octet-stream`), fetched from IPFS |

Rules: send `Authorization: Bearer <token>`. Files are at most **5 MB**. The `label` is stored **unencrypted** (letters, digits, space and `._()-`, 1 to 40 characters), so it must never hold personal details. `assetId` is a lower-case UUIDv4. `iv` is exactly 12 bytes, public keys exactly 33 bytes. Someone else's file looks like it does not exist (`404`), a company asking for user-only endpoints gets `403`. If IPFS is down, nothing is recorded and the answer is `502 STORAGE_UNAVAILABLE`. **The browser recomputes the CID of every file it fetches and refuses mismatches.**

### M3: requests, approval and access (built)
| Method + path | Who | What |
|---|---|---|
| `GET /api/policy` | anyone | The rules: purposes with the fields each may ask for, and the min/max duration (30 s to 24 h) |
| `GET /api/access-key` | user | The access service's public key. The person's browser makes kfrags **for this key**. |
| `POST /api/org/requests` | company | `{subject, field, purpose, durationSec}` -> `201 {requestId, status:"pending"}` |
| `GET /api/org/requests` | company | The company's own requests with status (`pending`, `approved`, `denied`, `expired`, `revoked`). A company never sees file or grant IDs. |
| `POST /api/org/requests/{id}/access` | company | Collect the data -> `{requestId, field, value}`. **Only that one value, never the file.** |
| `GET /api/user/requests` | user | Requests addressed to the caller |
| `POST /api/user/requests/{id}/approve` | user | `{assetId, kfrags:[b64]}` -> `{status:"approved", grantId, expiresAt}`. The person picks which of their files to share from. |
| `POST /api/user/requests/{id}/deny` | user | -> `{status:"denied"}` |

**Rules (the policy engine):** a request names a **purpose** (`DELIVERY`, `KYC`, `CONSULTATION`) and **one field** (`address`, `name`, `phone`, `blood_group`), and the purpose must allow that field (`PURPOSE_NOT_ALLOWED` otherwise). A request can be decided **once**. Someone else's request looks like it does not exist (`404`). The gateway checks the grant and the clock, and **the proxy checks revoke and expiry again on its own**.

**Internal doors** (shared secret in `X-Internal-Secret`, never reachable from a browser): proxy `POST /internal/policies`, `POST /internal/reencrypt`, `DELETE /internal/policies/{grantId}`; access service `GET /internal/public-key`, `POST /internal/open`. The proxy keeps its pieces in `.data/proxy.db`, **including a blocklist of revoked kfrags**, so a restart can never bring back a revoked permission.

New error codes: `PURPOSE_NOT_ALLOWED`, `BAD_KFRAG`, `KFRAG_REVOKED`, `REQUEST_NOT_APPROVED`, `GRANT_UNAVAILABLE` (the proxy lost it: approve again), `SERVICE_UNAVAILABLE`, `ACCESS_FAILED`, `FIELD_NOT_FOUND`.

## 2. Endpoints (REST, JSON), full plan

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
Codes: `UNAUTHENTICATED`, `FORBIDDEN`, `GRANT_REVOKED`, `GRANT_EXPIRED`, `PROOF_INVALID`, `SIGNALS_MISMATCH`, `NONCE_REUSED`, `NOT_FOUND`, `BAD_REQUEST`, `CONFLICT`, `FILE_TOO_LARGE`, `STORAGE_UNAVAILABLE`.

## 4. Open questions (decide this week)
1. How does FastAPI verify Groth16 proofs: Node subprocess calling snarkjs, or a Python verifier? (A + C)
2. Where are wrapped DEKs and metadata stored for the MVP: SQLite or Postgres? (C + D)
3. Does the browser upload to IPFS directly, or through the backend? **Proposal: through the backend** (browser sends ciphertext, backend talks to Kubo), because Kubo's API gives full control of the node and must never be exposed. The browser always recomputes the CID of what it fetches (tested in `spikes/ipfs`). (B + D)
4. Authentication for users and orgs: simple email+password with JWT for the MVP? (D + C)
5. **Answered in M3:** kfrags are signed by the owner's signing key, and the proxy verifies them against the owner's key, the file's key and the access service's key. The browser never talks to the proxy: the gateway checks the person's session first, then forwards the pieces with the internal secret. Still open for the report: the gateway is trusted to pass them on honestly (it is the operator).
