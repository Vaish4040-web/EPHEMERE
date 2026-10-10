"""Step 2 of the browser <-> Python test: open a bundle that the BROWSER created.

Usage:  python verify_bundle.py bundle.json
The browser made the keys, encrypted the file and created the permission pieces (kfrags).
Here the Python proxy and access service use them, exactly like the real server will.
"""
import base64
import hashlib
import json
import sys
import time

from umbral_pre import PublicKey, SecretKey

from server_side import AccessService, Proxy

b = base64.b64decode
bundle = json.load(open(sys.argv[1]))
secret = json.load(open("bob_secret.json"))

access = AccessService(secret_key=SecretKey.from_be_bytes(b(secret["secretKey"])))
owner_pk = PublicKey.from_compressed_bytes(b(bundle["ownerPk"]))
verifying_pk = PublicKey.from_compressed_bytes(b(bundle["verifyingPk"]))

proxy = Proxy()
proxy.store("grant-1", [b(k) for k in bundle["kfrags"]], time.time() + 3600, verifying_pk, owner_pk, access.public_key)
cfrags = proxy.reencrypt("grant-1", b(bundle["capsule"]))
plain = access.open_file(
    asset_id=bundle["assetId"], capsule_b=b(bundle["capsule"]), cfrags_b=cfrags,
    wrapped_dek=b(bundle["wrappedDek"]), iv=b(bundle["iv"]),
    file_ciphertext=b(bundle["fileCiphertext"]), owner_pk=owner_pk, verifying_pk=verifying_pk,
)
ok = hashlib.sha256(plain).hexdigest() == bundle["plaintextSha256"]
print("PASS  the Python server opened the file that the browser encrypted and shared" if ok
      else "FAIL  decrypted bytes do not match what the browser encrypted")
sys.exit(0 if ok else 1)
