"""Check that everything started by `python demo/run_all.py` really works.
Open a SECOND terminal and run:   python demo/check_m1.py        (add --no-web if you started with --no-web)
"""
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from api.common.config import Settings  # noqa: E402

s = Settings.from_env()
failures = 0


def check(name, ok, note=""):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   ({note})" if note else ""))
    if not ok:
        failures += 1


def call(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


good = {"X-Internal-Secret": s.internal_secret}
wrong = {"X-Internal-Secret": "wrong-secret-" + "x" * 20}
services = {"proxy": s.proxy_port, "access": s.access_port, "gateway": s.gateway_port}

for name, port in services.items():
    st, body = call(f"http://127.0.0.1:{port}/health")
    check(f"{name} is running (health)", st == 200 and name in body)

for name in ("proxy", "access"):
    port = services[name]
    check(f"{name}: internal door refuses calls with no secret", call(f"http://127.0.0.1:{port}/internal/ping")[0] == 401)
    check(f"{name}: internal door refuses the wrong secret", call(f"http://127.0.0.1:{port}/internal/ping", wrong)[0] == 403)
    check(f"{name}: internal door opens with the right secret", call(f"http://127.0.0.1:{port}/internal/ping", good)[0] == 200)

st, body = call(f"http://127.0.0.1:{s.gateway_port}/api/status")
status = json.loads(body) if st == 200 else {}
check("gateway reports every part is up", status.get("allOk") is True, ", ".join(f"{k}: {v['detail']}" for k, v in status.items() if isinstance(v, dict)))
check("gateway status does not leak the internal secret", s.internal_secret not in body)

db = s.data_dir / "ephemere.db"
tables = []
if db.exists():
    with sqlite3.connect(db) as conn:
        tables = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
check("database file exists with the 3 tables", {"assets", "requests", "grants"} <= set(tables), str(tables))

key_file = s.data_dir / "access_key.json"
check("access service key file exists", key_file.exists())
if key_file.exists() and os.name != "nt":
    check("access service key file is readable by the owner only", (key_file.stat().st_mode & 0o077) == 0)

ipfs_cfg = s.data_dir / "ipfs" / "config"
if ipfs_cfg.exists():
    api_addr = json.loads(ipfs_cfg.read_text())["Addresses"]["API"]
    check("IPFS control port listens on this computer only (127.0.0.1)", "127.0.0.1" in api_addr, api_addr)

if "--no-web" not in sys.argv:
    web = f"http://localhost:{s.web_port}"
    for path in ("/", "/vault", "/company", "/lab"):
        check(f"web page {path} opens", call(web + path)[0] == 200)
    st, body = call(web + "/api/status")
    check("the web app passes /api/status on to the gateway", st == 200 and json.loads(body).get("allOk") is True)

print("\nALL CHECKS PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(0 if failures == 0 else 1)
