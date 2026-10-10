# PRE spike (Member B): sharing an encrypted file safely

**What this proves, in simple words**

1. The **owner side** (JavaScript, like the browser) encrypts a file and creates "permission pieces" (kfrags).
2. The **server side** (Python, like FastAPI) uses those pieces to let the access service read the file, without ever giving keys to the company.
3. The two languages understand each other's data. (This was the biggest unknown.)
4. After **revoke**, the proxy refuses, and the revoked permission pieces cannot be registered again. After **expiry**, the proxy refuses.
5. **2-of-3 mode** works: one proxy alone cannot open the file, two together can.
6. The owner can still open their own file (this is allowed by our design).

## Files
| File | Role |
|---|---|
| `owner.mjs` | Owner side (browser code): encrypt file, wrap key, create kfrags, owner decrypt |
| `server_side.py` | `Proxy` (holds kfrags, enforces revoke and expiry) and `AccessService` (opens the file in memory) |
| `test_interop.py` | 14 tests across both languages |

## How to run (Windows)
**You need Python 3.11 exactly.** The library has no ready-made installer for Python 3.12 or newer, and it will fail with `Could not build wheels`. Check with `py -0`. If 3.11 is missing, install it from python.org (it can live next to your other Python).

Open the terminal inside this folder (`spikes/pre`) and run:

```
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
npm install
python test_interop.py
```

You should see 14 lines starting with `PASS` and then `ALL TESTS PASSED`.

## Results from my test run (Linux, Python 3.11, Node 22)
- Re-encrypt about 0.5 ms, verify and decrypt about 2 ms (tiny file, one kfrag). Measure again yourself for the report.
- Versions: umbral-pre **0.10.0** on both sides (npm `@nucypher/umbral-pre`, PyPI `umbral-pre`).

## Test with the browser (optional, 3 steps)
The web app (`web/`, page `/lab`) can make a bundle in the browser for this Python code to open:
1. `python make_bob.py` prints the access service's public key (and saves its secret in `bob_secret.json`, never commit it).
2. Paste the key into the page, click **Create share bundle**, and save the text as `bundle.json` in this folder.
3. `python verify_bundle.py bundle.json` should print `PASS`.

## Important lessons the tests show
- **The company must never be handed cfrags.** Test 7 shows that if someone keeps cfrags from before a revoke, they can still open the OLD capsule. That is why the access service (not the company) does the opening.
- **Strong revoke = re-key.** Test 8 shows that after the owner re-encrypts the file with a new key, the old cfrags are useless.
- The browser version of the same library was tested inside Next.js: see `web/`. A bundle made in a real browser is accepted by this Python code.

## Notes for the report
- umbral-pre is licensed **GPL-3.0**. Fine for an academic project, but mention it.
- The test harness passes secret keys between the two programs only so we can test across languages. In the real app the owner's secret key stays in the browser.
