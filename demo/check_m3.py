"""M3 check: the whole story through the REAL gateway, proxy, access service and IPFS (separate programs, real HTTP).
Python plays the part of Asha's browser (keys, encryption, permission pieces).

Start everything first (python demo/run_all.py), then in a second terminal:
    python demo/check_m3.py                  (about 5 seconds)
    python demo/check_m3.py --with-expiry    (adds a 35-second wait to prove the permission really ends)
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral_pre import PublicKey, SecretKey, Signer, encrypt, generate_kfrags

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from api.common.config import Settings  # noqa: E402

s = Settings.from_env()
G = f"http://127.0.0.1:{s.gateway_port}"
b64 = lambda b: base64.b64encode(b).decode()
failures = 0

PROFILE = {"name": "Asha Demo", "address": "Flat 4B, Rosewood Apartments, Example Road, Bengaluru 560001",
           "phone": "+91 90000 00000", "blood_group": "O+"}
MARKERS = [b"Rosewood", b"Bengaluru", b"Asha Demo", b"90000"]


def check(name, ok, note=""):
    global failures
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   ({note})" if note else ""))
    if not ok:
        failures += 1


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(G + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw.decode(errors="replace")}


def code(resp):
    return resp[1].get("error", {}).get("code")


def login(name):
    return call("POST", "/api/demo/login", {"account": name})[1]["token"]


class Browser:
    """What Asha's browser does, in Python."""

    def __init__(self):
        self.sk = SecretKey.random()
        self.pk = self.sk.public_key()
        self.signer = Signer(SecretKey.random())

    def upload(self, token, plaintext: bytes):
        asset_id = str(uuid.uuid4())
        dek, iv = os.urandom(32), os.urandom(12)
        ct = AESGCM(dek).encrypt(iv, plaintext, asset_id.encode())
        capsule, wrapped = encrypt(self.pk, dek)
        st, body = call("POST", "/api/assets", {
            "assetId": asset_id, "label": "profile.json", "iv": b64(iv), "capsule": b64(bytes(capsule)),
            "wrappedDek": b64(bytes(wrapped)), "ownerPk": b64(self.pk.to_compressed_bytes()),
            "verifyingPk": b64(self.signer.verifying_key().to_compressed_bytes()), "ciphertext": b64(ct)}, token)
        assert st == 201, body
        return asset_id

    def approve(self, token, request_id, asset_id):
        pk = PublicKey.from_compressed_bytes(base64.b64decode(call("GET", "/api/access-key", token=token)[1]["publicKey"]))
        kfrags = [b64(bytes(k)) for k in generate_kfrags(self.sk, pk, self.signer, 1, 1, True, True)]
        return call("POST", f"/api/user/requests/{request_id}/approve", {"assetId": asset_id, "kfrags": kfrags}, token)


def ask(token, field="address", purpose="DELIVERY", duration=600, subject="asha"):
    return call("POST", "/api/org/requests", {"subject": subject, "field": field, "purpose": purpose, "durationSec": duration}, token)


asha, ravi, qd, fm = (login(n) for n in ("asha", "ravi", "quickdeliver", "freshmart"))
me = Browser()
asset = me.upload(asha, json.dumps(PROFILE).encode())
check("Asha uploads her encrypted profile", bool(asset))

st, req = ask(qd)
rid = req.get("requestId")
check("QuickDeliver asks for Asha's address (delivery, 10 minutes)", st == 201 and req["status"] == "pending")
check("the purpose rule: delivery cannot ask for a blood group", code(ask(qd, field="blood_group")) == "PURPOSE_NOT_ALLOWED")
check("a company cannot ask for a field outside the allowed list", ask(qd, field="password")[0] == 422)
check("before approval: no data", code(call("POST", f"/api/org/requests/{rid}/access", token=qd)) == "REQUEST_NOT_APPROVED")

inbox = call("GET", "/api/user/requests", token=asha)[1]["requests"]
check("Asha sees the request in her inbox", any(r["requestId"] == rid and r["org"] == "QuickDeliver" for r in inbox))
check("Ravi does not see it, and cannot decide it", call("GET", "/api/user/requests", token=ravi)[1]["requests"] == []
      and call("POST", f"/api/user/requests/{rid}/deny", token=ravi)[0] == 404)

st, ok = me.approve(asha, rid, asset)
check("Asha approves, using her own keys", st == 200 and ok["status"] == "approved", f"until epoch {ok.get('expiresAt')}")
check("approving twice is refused", me.approve(asha, rid, asset)[0] == 409)

st, got = call("POST", f"/api/org/requests/{rid}/access", token=qd)
check("QuickDeliver receives the address", st == 200 and got.get("value") == PROFILE["address"])
check("...and ONLY the address (nothing else from the file)", set(got) == {"requestId", "field", "value"}
      and not any(v in json.dumps(got) for v in ("Asha Demo", "90000", "O+", "blood_group")))
check("FreshMart cannot use QuickDeliver's permission", call("POST", f"/api/org/requests/{rid}/access", token=fm)[0] == 404)
check("it keeps working while the permission lasts", call("POST", f"/api/org/requests/{rid}/access", token=qd)[0] == 200)

# a stranger's keys cannot grant access to Asha's file
st2, req2 = ask(qd, field="name")
bad = Browser().approve(asha, req2["requestId"], asset)
check("permission pieces from someone else's keys are refused", bad[0] == 422 and code(bad) == "BAD_KFRAG")
check("...and the request stays pending", [r["status"] for r in call("GET", "/api/user/requests", token=asha)[1]["requests"] if r["requestId"] == req2["requestId"]] == ["pending"])

st3, req3 = ask(qd, field="phone")
call("POST", f"/api/user/requests/{req3['requestId']}/deny", token=asha)
check("a denied request gives nothing", code(call("POST", f"/api/org/requests/{req3['requestId']}/access", token=qd)) == "REQUEST_NOT_APPROVED")

# nothing readable is stored anywhere in the backend's data folder
def scan_for(markers, root, reader=Path.read_bytes):
    """Search every stored file for the markers. On Windows, programs that are running keep some files locked
    (for example IPFS's repo.lock, which holds no data). Those lock files are skipped; any OTHER unreadable
    file is reported, never silently ignored."""
    found, locked, unreadable, scanned = [], [], [], 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            data = reader(path)
        except OSError:
            (locked if path.name.lower() in ("repo.lock", "lock") or path.suffix.lower() == ".lock" else unreadable).append(path.name)
            continue
        scanned += 1
        found += [f"{m.decode()} in {path.relative_to(root)}" for m in MARKERS if m in data]
    return found, locked, unreadable, scanned


found, locked, unreadable, scanned = scan_for(MARKERS, s.data_dir)
note = f"{scanned} files searched" + (f"; lock files skipped: {', '.join(sorted(set(locked)))}" if locked else "")
check("a search of ALL stored data (IPFS, databases, logs, keys) finds no plaintext", not found, note + ("; " + "; ".join(found[:3]) if found else ""))
if unreadable:
    print(f"WARN  could not read {len(unreadable)} file(s): {', '.join(sorted(set(unreadable))[:5])}  (not counted as searched)")

if "--with-expiry" in sys.argv:
    st4, req4 = ask(qd, field="name", duration=30)
    me.approve(asha, req4["requestId"], asset)
    check("a 30-second permission works at first", call("POST", f"/api/org/requests/{req4['requestId']}/access", token=qd)[0] == 200)
    print("      ...waiting 32 seconds for it to run out", flush=True)
    time.sleep(32)
    res = call("POST", f"/api/org/requests/{req4['requestId']}/access", token=qd)
    check("after the time is up, it is refused", res[0] == 403 and code(res) == "GRANT_EXPIRED")
    check("the company's list now says 'expired'", [r["status"] for r in call("GET", "/api/org/requests", token=qd)[1]["requests"] if r["requestId"] == req4["requestId"]] == ["expired"])

print("\nALL CHECKS PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(0 if failures == 0 else 1)
