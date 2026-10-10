"""Step 1 of the browser <-> Python test: make the ACCESS SERVICE's key pair.

Prints the PUBLIC key (paste it into the web page's self-test) and saves the SECRET key to
bob_secret.json (test file only; never commit it, it is in .gitignore).
"""
import base64
import json

from umbral_pre import SecretKey

sk = SecretKey.random()
with open("bob_secret.json", "w") as f:
    json.dump({"secretKey": base64.b64encode(sk.to_be_bytes()).decode()}, f)
print(base64.b64encode(sk.public_key().to_compressed_bytes()).decode())
