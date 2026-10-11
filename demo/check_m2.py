"""M2 check: uploading, listing and fetching encrypted files through the real gateway and the real IPFS node.
Start everything first (python demo/run_all.py), then in a second terminal:   python demo/check_m2.py
(The browser does the real encryption; here we upload random bytes that stand in for ciphertext.)
"""
import base64
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from api.common.config import Settings  # noqa: E402

s = Settings.from_env()
GATEWAY = f"http://127.0.0.1:{s.gateway_port}"
failures = 0
b64 = lambda b: base64.b64encode(b).decode()


def check(name, ok, note=""):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   ({note})" if note else ""))
    if not ok:
        failures += 1


def call(method, url, body=None, token=None):
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jcall(*a, **k):
    st, raw = call(*a, **k)
    try:
        return st, json.loads(raw)
    except ValueError:
        return st, raw


def login(name):
    st, body = jcall("POST", f"{GATEWAY}/api/demo/login", {"account": name})
    return body["token"] if st == 200 else None


asha, ravi, org = login("asha"), login("ravi"), login("quickdeliver")
check("demo sign-in works for Asha, Ravi and QuickDeliver", all([asha, ravi, org]))

cipher = os.urandom(3000)
asset_id = str(uuid.uuid4())
payload = {"assetId": asset_id, "label": "check-m2.bin", "iv": b64(os.urandom(12)), "capsule": b64(os.urandom(105)),
           "wrappedDek": b64(os.urandom(60)), "ownerPk": b64(os.urandom(33)), "verifyingPk": b64(os.urandom(33)),
           "ciphertext": b64(cipher)}

check("no token: refused", jcall("GET", f"{GATEWAY}/api/assets")[0] == 401)
check("a company cannot upload", jcall("POST", f"{GATEWAY}/api/assets", payload, org)[0] == 403)

st, up = jcall("POST", f"{GATEWAY}/api/assets", payload, asha)
check("Asha uploads a file", st == 201 and str(up.get("cid", "")).startswith("baf"), str(up.get("cid", ""))[:30] + "...")
cid = up.get("cid", "")

st, body = call("POST", f"{s.ipfs_url}/api/v0/cat?arg={cid}&timeout=10s")
check("the real IPFS node holds exactly the bytes that were uploaded", st == 200 and body == cipher)

st, listing = jcall("GET", f"{GATEWAY}/api/assets", token=asha)
check("Asha sees the file in her list", st == 200 and any(a["assetId"] == asset_id for a in listing["assets"]))
check("Ravi does not see it", asset_id not in [a["assetId"] for a in jcall("GET", f"{GATEWAY}/api/assets", token=ravi)[1]["assets"]])
check("Ravi cannot fetch it (looks like it does not exist)", jcall("GET", f"{GATEWAY}/api/assets/{asset_id}", token=ravi)[0] == 404
      and call("GET", f"{GATEWAY}/api/assets/{asset_id}/ciphertext", token=ravi)[0] == 404)
check("a company cannot fetch it", call("GET", f"{GATEWAY}/api/assets/{asset_id}/ciphertext", token=org)[0] == 403)

st, back = call("GET", f"{GATEWAY}/api/assets/{asset_id}/ciphertext", token=asha)
check("Asha downloads the same bytes back through the gateway", st == 200 and back == cipher)

st, again = jcall("POST", f"{GATEWAY}/api/assets", payload, asha)
check("uploading the same asset ID twice is refused", st == 409)
check("a file over 5 MB is refused", jcall("POST", f"{GATEWAY}/api/assets", dict(payload, assetId=str(uuid.uuid4()), ciphertext=b64(b"\0" * 5_000_001)), asha)[0] == 413)

db = s.data_dir / "ephemere.db"
raw = db.read_bytes() if db.exists() else b""
check("the database file does not contain the file bytes (only metadata)", cipher[:64] not in raw)
with sqlite3.connect(db) as conn:
    cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)")]
check("the database has the M2 columns", {"label", "cid", "size_bytes", "wrapped_dek"} <= set(cols))

print("\nALL CHECKS PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(0 if failures == 0 else 1)
