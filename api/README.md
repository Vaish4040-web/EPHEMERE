# Backend (`api/`): three small servers

| Server | Port | What it does (now, and later) |
|---|---|---|
| **Gateway** | 8000 | The only server the web pages talk to. Now: health and a status report. Later: requests, approvals, access, revoke, audit. |
| **Proxy** | 8001 | Holds the permission pieces (kfrags) in `.data/proxy.db`, makes cfrags, refuses after revoke or expiry, and never lets a revoked piece come back. It can never read a file. |
| **Access service** | 8002 | Recovers the file key and decrypts **in memory only**, then returns just the one requested field. Its own key pair is created once and kept in `.data/access_key.json`. |

IPFS (port 5101) and the web app (port 3000) are started by `python demo/run_all.py` too.

## The "internal door"
The proxy and the access service only answer calls that carry the shared secret in the header `X-Internal-Secret`. Only the gateway has it. The secret lives in `.env` at the top of the repo (`run_all.py` creates it the first time, and it is never committed).

- No secret: error `UNAUTHENTICATED` (401)
- Wrong secret: error `FORBIDDEN` (403)

## Run the tests
At the top of the repo, with your virtual environment active:

```
python -m pytest -q
```

You should see **128 passed**. The tests were written before the code. They check, among other things, that the doors refuse missing or wrong secrets, that the access key is created once and reused, that the key is never shown in any answer, and that the gateway reports a broken service honestly.

## What the gateway can do now (M2)
| Endpoint | What |
|---|---|
| `POST /api/demo/login` | Sign in as a demo account (asha, ravi, quickdeliver). **No passwords: demo only, not real security.** Switch off with `DEMO_LOGIN=off`. |
| `POST /api/assets` | Upload an encrypted file (the browser encrypts it first). Stored in IPFS; the database keeps metadata only. |
| `GET /api/assets`, `GET /api/assets/{id}`, `.../ciphertext` | List, describe and download your own files. Someone else's file looks like it does not exist. |

**M3 adds the story:** `GET /api/policy`, `GET /api/access-key`, `POST /api/org/requests`, `GET /api/org/requests`, `POST /api/org/requests/{id}/access`, `GET /api/user/requests`, `POST /api/user/requests/{id}/approve` and `/deny`. A company names a purpose and ONE field; the person approves in their browser; the company gets only that value.

Full details are in `docs/interface-contract.md` (section 2a). Check it live with `python demo/check_m2.py` and `python demo/check_m3.py` (add `--with-expiry` for a real 35-second expiry test).

## Folders
| Folder | Contents |
|---|---|
| `common/` | Settings, the one error format, the internal-door check |
| `gateway/` | `main.py` (builds the server), `auth.py` (demo sign-in), `assets.py` (files), `requests.py` (the policy engine: ask, approve, access), `internal.py` (talks to proxy and access service), `ipfs.py`, `db.py` (SQLite) |
| `proxy/` | `main.py` (the doors) and `store.py` (durable permission store) |
| `access/` | `main.py` (opens a file in memory, returns one field) |
| `common/` | Settings, the one error format, the internal-door check, `policy.py` (purposes and fields) |
| `tests/` | The tests |

## Rules (from `docs/PROJECT_CONTEXT.md`)
Never log or return secrets or keys. Never store plaintext. Every allow or deny decision will write an audit event. Write the failing test first.
