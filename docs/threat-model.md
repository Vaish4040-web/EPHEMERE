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
| T1 after expiry | Expiry enforced by proxy | Org retries after `expiresAt` → denied |
| T2 | AES-GCM-256 before upload; IPFS is not the privacy mechanism | Fetch CID directly → ciphertext only |
| T3 | No plaintext at rest; only metadata and wrapped keys stored | Run the flow with a known marker string inside the test file, then search logs, temp folders, DB dump and crash output. **Pass = the marker is found nowhere.** |
| T4 | Threshold kfrags (stretch goal); eviction receipts as evidence. **MVP uses 1-of-1, so one compromised proxy node is a full break. Say this openly.** | 2-of-3 test: one node alone cannot decrypt (done in `spikes/pre`) |
| T4b Replayed kfrag | Proxy keeps a blocklist of revoked kfrags and refuses revoked grant ids | Re-register a revoked kfrag (same or new grant id) → refused (done in `spikes/pre`) |
| T5 | Issuer signature verified inside the circuit | Forged and edited credential cannot produce a proof (done in `circuits/`) |
| T6 | Hash-chained Merkle log with inclusion proofs | Altering one stored event fails verification |
| T7 | Verifier-chosen nonce bound into the proof; signals checked | Old proof against a new nonce is rejected (done in `circuits/`) |

## Out of scope / residual risks (say these out loud in the report)
- Data an organization legitimately saw in an authorized session cannot be recalled.
- A compromised running access service can read plaintext it is currently processing (transient RAM reduces persistence, it does not make memory invulnerable). Future work: confidential computing (TEE with attestation).
- A single-operator Merkle log proves tampering only if the root is published or witnessed somewhere the operator does not control. For the demo, show root verification and a deliberately altered event.
- Dev-only trusted setup for Groth16, and a simulated credential issuer.
- Proxy and access service may share a machine in the demo (separate processes), which weakens T4 compared with independent nodes.
- DPDP: the system technically supports selected principles (minimization, purpose/duration limits, erasure/revocation workflow). It is not a legal compliance certificate.
