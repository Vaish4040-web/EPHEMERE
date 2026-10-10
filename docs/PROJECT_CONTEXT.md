# EPHEMERE: Project Context

> Read this first. Humans and AI agents both. If code and this file disagree, stop and ask the team.

## 1. What we are building
A zero-trust middleware between **users (data principals)** and **organizations (data fiduciaries)**:

1. The user encrypts personal files **in the browser** (AES-GCM-256) and stores the ciphertext on **IPFS**.
2. An organization requests data or an attribute, stating **purpose and duration**.
3. The middleware runs a zero-trust decision: authenticate, authorize, consent, expiry/revocation, and a **zk-SNARK** check when an attribute proof is needed (for example age ≥ 18).
4. If allowed, **Proxy Re-Encryption (Umbral)** lets the middleware's access service obtain the file key without the owner being online.
5. The access service decrypts **only inside process memory**, performs the operation, and discards everything.
6. Every decision (allow, deny, grant, revoke) is appended to a **Merkle log**. No personal data goes in the log.

## 2. Security goals (agreed wording)
- **Revocation goal:** after the user revokes (or a grant expires), the organization **cannot obtain any new access**. The owner may still decrypt their own files. That is acceptable.
- **Minimization:** the organization learns only the requested attribute result, not the document.
- **Audit:** history cannot be altered without detection (tamper-evident, not "unhackable").
- **Honest limits (state them in the report):** anything an organization legitimately saw during an authorized session cannot be taken back; a compromised running server can expose plaintext it is currently processing; IPFS is not private by itself, so encryption is the confidentiality mechanism; DPDP wording must stay "technically supports selected principles", not "guarantees compliance".

## 3. Key design decisions (change only by team agreement)
| # | Decision |
|---|---|
| D1 | One random 32-byte **data key (DEK) per file**. File encrypted with AES-GCM-256, fresh random 12-byte IV every time. |
| D2 | The DEK is wrapped with **Umbral** under the owner's key (`encrypt` → capsule + wrapped DEK). Ciphertext on IPFS (CID), wrapped DEK and metadata in the DB. |
| D3 | The **delegate** is the middleware's access service, never the organization. The organization never receives cfrags or the DEK. |
| D4 | The **proxy** (stores kfrags, produces cfrags) and the **access service** (decrypts in RAM) are **separate FastAPI apps on separate ports**, even on one machine, so they can be split later. |
| D5 | Kfrags are generated **in the browser** (owner's secret key never leaves it). MVP: threshold 1-of-1. Later: 2-of-3 if time allows. |
| D6 | The proxy refuses to produce a cfrag if the grant is revoked or expired, and revocation deletes the kfrags and blocklists them so they cannot be re-registered. Optional "strong revoke": owner re-keys the file (new DEK, new CID). |
| D7 | ZK: Circom 2.1.9 + SnarkJS Groth16. Verifier checks the proof **and** that public signals equal its own issuer key, cutoff day and nonce. Dev-only trusted setup, simulated issuer. |
| D8 | Audit: hash-chained events, Merkle root checkpoints, inclusion proofs. Events contain IDs and decisions only. |

## 4. Stack and pinned versions
| Layer | Tech |
|---|---|
| Frontend | Next.js (Node 20+ LTS), WebCrypto for AES-GCM |
| ZK | Circom 2.1.9, snarkjs 0.7.6, circomlib 2.0.5, circomlibjs 0.1.7 |
| PRE | **umbral-pre 0.10.0**: npm `@nucypher/umbral-pre` (browser/WASM) and PyPI `umbral-pre` (FastAPI). Pin **both to 0.10.0**; interop was tested and works (see `spikes/pre`). License is GPL-3.0, mention it in the report. pyUmbral (`umbral` on PyPI) is inactive: do not use. |
| Storage | IPFS Kubo (local node) |
| Backend | **Python 3.11 exactly**, FastAPI. umbral-pre has no ready-made installer for Python 3.12+, so use 3.11 for the whole team. |
| Audit | Python module `audit/` (standard `hashlib` + `cryptography` for Ed25519 checkpoint signatures) |

## 5. Ownership
| Member | Owns | Folder |
|---|---|---|
| A | ZK circuits, browser proving, proof benchmarks | `circuits/` |
| B | Browser + server crypto: AES-GCM, Umbral flow, revocation/re-key | `web/src/crypto`, `api/proxy`, `api/access` (crypto parts) |
| C | FastAPI orchestration, policy engine, transient-RAM handling, Merkle log, leak tests | `api/`, `audit/` |
| D | Next.js user vault and company portal, auth, IPFS upload/fetch, consent dashboard | `web/` |

One branch per task (`a/zk-browser`, `b/pre-flow`, ...). Pull requests into `main`, one reviewer, **crypto code is reviewed by someone who did not write it**.

## 6. Rules for AI agents and humans
**Crypto**
- Use only: WebCrypto, umbral-pre, snarkjs/circomlib, and in Python `hashlib` and the `cryptography` package. **Never write custom crypto or invent primitives.**
- AES-GCM IV: fresh random 12 bytes per encryption, never reused, stored with the ciphertext.
- Randomness only from `crypto.getRandomValues` / `crypto.randomBytes` / `secrets`. **Never `Math.random()`/`random`.**
- Never hardcode, log, or commit keys, DEKs, plaintext, `.env` files or `keys/`.
- Never skip or stub verification (proofs, signatures, cfrag verification) to make something pass.
- Verify every library call against the **official docs**. If unsure an API exists, say so instead of guessing.

**Backend**
- Plaintext lives only in local variables for the duration of a request. No temp files, no logging of request bodies, no caching of decrypted data. Overwrite key buffers where the language allows.
- Every allow/deny decision writes an audit event.

**Process**
- **Tests first.** Write the failing attack tests (revoked org denied, expired grant denied, replayed nonce rejected, tampered audit event detected), then implement.
- Ask before adding any dependency. Check package names exactly.
- Do not change the interface contract without updating `docs/interface-contract.md` in the same PR.
- Do not claim a feature works unless the test ran and passed.

## 7. Status
- [x] ZK spike: age proof circuit + attack tests (`circuits/`)
- [x] PRE spike: encrypt, delegate, re-encrypt, revoke, expiry, 2-of-3, re-key; JS ↔ Python interop passes (`spikes/pre`). **Still to do:** run the JS side inside a real browser (Next.js)
- [x] Merkle log spike: hash chain, Merkle root, inclusion + consistency proofs, signed checkpoints, tamper attacks (`audit/`)
- [ ] AES-GCM + IPFS spike: encrypt in browser, store, fetch by CID, decrypt
- [ ] Interface contract agreed (`docs/interface-contract.md`)
- [ ] Walking skeleton: one user, one org, one file, grant, access, revoke, denied
