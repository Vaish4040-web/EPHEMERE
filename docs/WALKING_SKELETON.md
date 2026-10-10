# EPHEMERE: Walking Skeleton Plan (v0.1, draft for the team)

> A "walking skeleton" is the smallest version of the whole system where **every part is real and connected**, even if it is plain and ugly. We build it first, then make each part better.
> Read `docs/PROJECT_CONTEXT.md` first. This file says *what to build next and in what order*.

## Progress
| Step | Status |
|---|---|
| M0 Decisions and contract v1.0 | [ ] Team meeting still to do. M1 was built using the suggestions in section 5; tell us if the team chooses differently. |
| M1 Services run | [x] **Built and tested.** One command (`python demo/run_all.py`) starts IPFS, proxy, access service, gateway and the web app. The vault and company pages show live status. 15 backend tests, 20 integration checks, and a real-browser check pass. |
| M2 Upload a file | [ ] |
| M3 Request, approve, access | [ ] |
| M4 Revoke, expiry, audit events | [ ] |
| M5 The age proof | [ ] |
| M6 Prove the history | [ ] |
| M7 Demo, end-to-end test, measurements | [ ] |

## 1. The story we build
**Asha** has a profile file that includes her delivery address. **QuickDeliver** sells an age-restricted item. It asks for two things:

1. proof that Asha is **18 or older** (zero-knowledge proof, no date of birth shared)
2. her **address** for **10 minutes**, for the purpose **DELIVERY**

Asha approves in her browser. QuickDeliver receives **only the address**, never the file. Then Asha **revokes**, and QuickDeliver is **refused**. Every step goes into the audit log, and Asha (or an auditor) can check that the log was not changed.

Why this story: it uses every building block (encryption, IPFS, secure sharing, zero-knowledge proof, data minimization, revocation, audit) and it matches the delivery application on our slides.

## 2. The parts
| Part | What it does | Runs where |
|---|---|---|
| Vault page (Asha) | Keeps her keys, encrypts files, makes the age proof, creates permission pieces (kfrags), approves or revokes | Browser |
| Company page (QuickDeliver) | Sends a request, asks for the data | Browser |
| **Gateway** | Checks the rules, verifies the proof, talks to the other parts, writes the audit log, stores metadata | FastAPI server |
| **Proxy** | Holds kfrags, produces cfrags, refuses after revoke or expiry. Can never read a file. | FastAPI server |
| **Access service** | Recovers the file key, decrypts **in memory only**, returns only the requested field | FastAPI server |
| IPFS (Kubo) | Stores encrypted files only | Local node, `--offline` |
| Database (SQLite) | Metadata: assets, requests, grants | One file |
| Auditor script | Keeps old checkpoints and checks the log was only appended to | Separate small program |

The browser pages talk **only to the gateway**. IPFS's control port is never exposed.

## 3. The six steps of the story
1. **Asha uploads.** Her browser encrypts the file (AES-GCM), the gateway stores the ciphertext in IPFS and saves the CID, IV, capsule and wrapped key.
2. **QuickDeliver asks.** The gateway creates a request with a fresh challenge (nonce and cutoff day) and writes `REQUEST_CREATED` to the log.
3. **Asha approves.** Her browser makes the age proof for that challenge and creates kfrags for the access service. The gateway verifies the proof (`ZK_VERIFIED`), gives the kfrags to the proxy with an expiry, and writes `GRANT_APPROVED`.
4. **QuickDeliver gets the data.** The gateway checks the grant, the proxy returns cfrags, the access service decrypts in memory and returns **only** the `address` field. `ACCESS_ALLOWED` is logged.
5. **Asha revokes.** The proxy deletes the kfrags and blocklists them. `REVOKED` is logged.
6. **QuickDeliver tries again.** The proxy refuses. `ACCESS_DENIED` is logged. The auditor then checks the log, and a deliberate edit to the log is caught.

## 4. Build order (every step ends with something you can see working)
| Step | What gets built | Who leads | What you can see |
|---|---|---|---|
| **M0** | Agree the decisions in section 5, finish the interface contract as **v1.0**, merge the open pull requests | Everyone | Contract marked v1.0 |
| **M1** | Gateway, proxy and access service start with health checks. IPFS and SQLite are ready. Both page shells open. | C (B helps), D for the pages | One command starts everything |
| **M2** | Upload a file | D, B, C | Asha uploads, the CID appears, IPFS holds only scrambled data |
| **M3** | Request, approve, access (no age proof yet) | B, C, D | QuickDeliver receives only the address |
| **M4** | Revoke, expiry, audit events for every decision | C, B | Refused after revoke or expiry, and the history lists every step |
| **M5** | The age proof | A, C, D | An adult passes, a 15-year-old is blocked |
| **M6** | Prove the history | C, A | Auditor says OK; after an edit it says ALERT |
| **M7** | Demo script, automatic end-to-end test, measurements | Everyone | One test plays the whole story in a real browser; numbers for the report |

**Time guess: about 3 to 4 weeks for four people working part-time.** This is only a guess. Re-estimate after M1.

**Rules for every step**
- **Tests first.** Write the failing test (for example "revoked company is refused"), then make it pass.
- Each step ends with something runnable that a teammate can try.
- One branch per step (for example `c/m1-services`). Pull request, one reviewer. Crypto code is reviewed by someone who did not write it.
- Do not change the interface contract without updating `docs/interface-contract.md` in the same pull request.

## 5. Decisions for the team meeting (30 minutes)
Tick a box when the team has agreed. Write the final choice in the last column.

| Done | # | Question | My suggestion | Why | Team's final choice |
|---|---|---|---|---|---|
| [ ] | 1 | Which demo story? | Age-restricted delivery | Uses every building block | |
| [ ] | 2 | How does the gateway check ZK proofs? | A small Node script it calls (`snarkjs`) | Already works; a Python checker would be hard | |
| [ ] | 3 | Which database? | SQLite | One file, nothing to install | |
| [ ] | 4 | How do people log in? | Fixed demo accounts with tokens, labelled "demo only" | Real login is its own project | |
| [ ] | 5 | How does the browser reach IPFS? | Through the gateway | Never expose IPFS's control port | |
| [ ] | 6 | Who keeps audit checkpoints? | Auditor script first, user's browser later | Simplest way to show tampering is caught | |
| [ ] | 7 | How many server processes? | Three small FastAPI apps (gateway, proxy, access), started together | Matches decision D4 | |

Also decide: **who is C, who is D** and so on, if the roles are not already clear, and which day each person will run the self-test page (`/lab`) on their own laptop.

## 6. Proposed technical notes (change if the team disagrees)
- **Ports:** web 3000, gateway 8000, proxy 8001, access service 8002, IPFS API 5001 (internal only).
- **One command to start everything:** `python demo/run_all.py` (works on Windows, Mac and Linux).
- **Service-to-service calls** carry a shared secret in a header (from a `.env` file that is never committed). The proxy and access service accept calls only from the gateway.
- **Database tables (sketch):** `assets` (id, owner, cid, iv, capsule, wrapped key, owner public keys), `requests` (id, org, asset, field, needs age proof, purpose, duration, status, nonce, cutoff day), `grants` (id, request, status, expires at).
- **Allowed purposes** are a fixed list of codes (for example `DELIVERY`). Free text is never accepted.
- **Field extraction:** the access service reads the decrypted JSON, returns only the requested field, and drops the rest.
- **End-to-end test:** a browser-driven test (Playwright) that plays the six steps and checks the results, including the refusal after revoke.

## 7. Done when
- [ ] One command starts everything.
- [ ] Asha uploads a file, and a search of the IPFS storage finds no plaintext.
- [ ] Asha approves a request in her browser (age proof and permission pieces).
- [ ] QuickDeliver receives **only the address**, never the file.
- [ ] After a revoke or expiry, QuickDeliver is refused.
- [ ] Every step is in the audit log, and an edit to the log is caught by the auditor.
- [ ] An automatic test plays the whole story in a real browser and passes.

## 8. Left out on purpose (for now)
Real login, several files or companies, 2-of-3 mode, the strong re-key, a polished design, deployment, and joining the public IPFS network.

## 9. Known limits to state in the report
- Asha's keys live in her browser. Clearing the browser data loses her files (no key backup yet).
- The issuer of the age credential is simulated, and the zero-knowledge setup is development-only.
- The proxy and access service may run on one machine in the demo, which is weaker than independent nodes.
- The audit log detects tampering only if someone besides the operator keeps an old checkpoint.
- Demo login is not real security.

## 10. Meeting notes
(Write the date, who came, and what was decided.)
