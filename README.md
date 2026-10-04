# EPHEMERE

A Decentralized Zero-Trust Middleware Framework for DPDP Act Compliance using zk-SNARKs and Proxy Re-Encryption.

Start here: [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) (architecture, rules, ownership), then [`docs/interface-contract.md`](docs/interface-contract.md).

| Folder | Owner | Contents |
|---|---|---|
| `circuits/` | A | Circom + SnarkJS age proof (spike done) |
| `web/` | D | Next.js user vault + company portal |
| `api/` | B, C | FastAPI: proxy, access service, policy engine |
| `audit/` | C | Append-only Merkle log |
| `demo/` | all | End-to-end demo script |
| `docs/` | all | Context, interface contract, threat model |
