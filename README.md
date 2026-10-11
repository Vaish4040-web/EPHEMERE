# EPHEMERE

A Decentralized Zero-Trust Middleware Framework for DPDP Act Compliance using zk-SNARKs and Proxy Re-Encryption.

Start here: [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) (architecture, rules, ownership), then [`docs/interface-contract.md`](docs/interface-contract.md).

## Quick start (Windows, Mac or Linux)
You need **Python 3.11 exactly**, **Node.js 20+** and Git. In the terminal, at the top of the repo:

```
py -3.11 -m venv .venv                  (Mac/Linux: python3.11 -m venv .venv)
.venv\Scripts\activate                  (Mac/Linux: source .venv/bin/activate)
pip install -r api/requirements-dev.txt
cd demo && npm install && cd ..         (downloads the IPFS program, about 120 MB, once)
cd web && npm install && cd ..
python demo/run_all.py
```

Then open **http://localhost:3000/vault** and **http://localhost:3000/company**. Press Ctrl+C to stop everything.
In a second terminal: `python demo/check_m1.py` checks that every part works, and `python -m pytest -q` runs the backend tests.

| Folder | Owner | Contents |
|---|---|---|
| `circuits/` | A | Circom + SnarkJS age proof (spike done) |
| `web/` | D | Next.js user vault + company portal |
| `api/` | B, C | FastAPI: gateway, proxy, access service (see `api/README.md`) |
| `audit/` | C | Append-only Merkle log |
| `demo/` | all | `run_all.py` starts everything, check scripts, later the end-to-end test |
| `docs/` | all | Context, interface contract, threat model |
