# Backend (`api/`): three small servers

| Server | Port | What it does (now, and later) |
|---|---|---|
| **Gateway** | 8000 | The only server the web pages talk to. Now: health and a status report. Later: requests, approvals, access, revoke, audit. |
| **Proxy** | 8001 | Later: holds the key pieces (kfrags), makes cfrags, refuses after revoke or expiry. It can never read a file. |
| **Access service** | 8002 | Later: recovers the file key and decrypts **in memory only**. Now: creates its own key pair once and keeps it in `.data/access_key.json`. |

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

You should see **46 passed**. The tests were written before the code. They check, among other things, that the doors refuse missing or wrong secrets, that the access key is created once and reused, that the key is never shown in any answer, and that the gateway reports a broken service honestly.

## What the gateway can do now (M2)
| Endpoint | What |
|---|---|
| `POST /api/demo/login` | Sign in as a demo account (asha, ravi, quickdeliver). **No passwords: demo only, not real security.** Switch off with `DEMO_LOGIN=off`. |
| `POST /api/assets` | Upload an encrypted file (the browser encrypts it first). Stored in IPFS; the database keeps metadata only. |
| `GET /api/assets`, `GET /api/assets/{id}`, `.../ciphertext` | List, describe and download your own files. Someone else's file looks like it does not exist. |

Full details are in `docs/interface-contract.md` (section 2a). Check it live with `python demo/check_m2.py`.

## Folders
| Folder | Contents |
|---|---|
| `common/` | Settings, the one error format, the internal-door check |
| `gateway/` | `main.py` (builds the server), `auth.py` (demo sign-in), `assets.py` (files), `ipfs.py` (talks to IPFS), `db.py` (SQLite) |
| `proxy/`, `access/` | One `main.py` each (`create_app()` builds the server) |
| `tests/` | The tests |

## Rules (from `docs/PROJECT_CONTEXT.md`)
Never log or return secrets or keys. Never store plaintext. Every allow or deny decision will write an audit event. Write the failing test first.
