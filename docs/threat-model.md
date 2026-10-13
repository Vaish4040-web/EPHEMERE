# EPHEMERE: Threat Model (outline, to be completed as modules land)

## Assets
- User files (plaintext), file keys (DEKs), owner Umbral secret key
- Kfrags held by the proxy; the access service's Umbral secret key
- Audit log integrity
- Attribute values behind proofs (date of birth, etc.)

## Adversaries
| ID | Adversary | Capability we assume |
|---|---|---|
| T1 | Curious/malicious **organization** | Authenticated API client; wants data after revocation or beyond purpose |
| T2 | **Storage observer** | Can read anything on IPFS (all ciphertexts and CIDs) |
| T3 | **Database/backend breach** | Reads the database and disk of the servers at rest |
| T4 | **Malicious proxy node** | Holds kfrags; may refuse, delay, or keep copies after revocation |
| T5 | **Dishonest user** | Tries to forge an attribute (fake date of birth) |
| T6 | **Log tamperer** | Insider who edits or deletes audit history |
| T7 | **Replay attacker** | Re-submits an old proof or request |

## Defences and the tests that prove them
| Threat | Defence | Test (must exist before claiming it) |
|---|---|---|
| T1 after revocation | Proxy denies cfrags; kfrags deleted; org never holds keys (D3) | Org retries after revoke → `GRANT_REVOKED` |
| T1 after expiry | Expiry enforced by the gateway AND by the proxy on its own | Org retries after expiry → `GRANT_EXPIRED` (done: unit tests, a proxy-only-clock test, and a real 30-second wait in `demo/check_m3.py --with-expiry`) |
| T1 asking for too much | A request must name a purpose and ONE field from a fixed list, and the purpose must allow it. Only that one value is ever returned. | `PURPOSE_NOT_ALLOWED`, unknown fields refused, response contains only `{requestId, field, value}` (done in `api/tests` and `demo/check_m3.py`) |
| T1 using another company's permission | Requests are private to the two parties; others see `404` | FreshMart tries QuickDeliver's request (done) |
| T2 | AES-GCM-256 before upload; IPFS is not the privacy mechanism | Fetch CID directly → ciphertext only |
| T3 | No plaintext at rest; only metadata and wrapped keys stored | Run the flow with a known marker string inside the test file, then search logs, temp folders, DB dump and crash output. **Pass = the marker is found nowhere.** (**Done in M3:** after a real approval and access, a search of everything under `.data/` (IPFS blocks, both databases, all logs, the access key) finds no marker; also asserted in `api/tests` for logs and disk.) |
| T4 | Threshold kfrags (stretch goal); eviction receipts as evidence. **MVP uses 1-of-1, so one compromised proxy node is a full break. Say this openly.** | 2-of-3 test: one node alone cannot decrypt (done in `spikes/pre`) |
| T4b Replayed kfrag | Proxy keeps a blocklist of revoked kfrags and refuses revoked grant ids | Re-register a revoked kfrag (same or new grant id) → refused (done in `spikes/pre`) |
| T5 | Issuer signature verified inside the circuit | Forged and edited credential cannot produce a proof (done in `circuits/`) |
| T6 | Hash-chained Merkle log, inclusion + consistency proofs, **signed checkpoints kept by users or auditors** | Edit, delete and swap are detected (done in `audit/`). A fully rebuilt log fails the consistency check against an old checkpoint (done in `audit/`). |
| T7 | Verifier-chosen nonce bound into the proof; signals checked | Old proof against a new nonce is rejected (done in `circuits/`) |

## Out of scope / residual risks (say these out loud in the report)
- **The access service sees plaintext in memory** while it opens a file. Python cannot promise to wipe memory, so the code only drops its references right away. A compromised access service is a full break for whatever it is opening at that moment.
- **The gateway is trusted** to pass permission pieces on honestly and to tell the browser the right access-service key. It is the operator.
- **Demo sign-in has no passwords.** Anyone who can reach the gateway can act as any demo account.
- **Keys live in the browser.** Clearing browser data loses the files for good.
- Data an organization legitimately saw in an authorized session cannot be recalled.
- A compromised running access service can read plaintext it is currently processing (transient RAM reduces persistence, it does not make memory invulnerable). Future work: confidential computing (TEE with attestation).
- A single-operator log proves tampering only if someone besides the operator holds an older checkpoint. Without that, cutting off the last events or rebuilding the whole log is undetectable (both are shown in `audit/test_audit.py`). Decide who stores checkpoints for the demo (for example the user's browser).
- Dev-only trusted setup for Groth16, and a simulated credential issuer.
- Proxy and access service may share a machine in the demo (separate processes), which weakens T4 compared with independent nodes.
- DPDP: the system technically supports selected principles (minimization, purpose/duration limits, erasure/revocation workflow). It is not a legal compliance certificate.
