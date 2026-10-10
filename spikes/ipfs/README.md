# IPFS spike (Members B + D): encrypt in the browser, store by content address

**What this proves, in simple words**

1. A file is **encrypted first** (AES-GCM-256, fresh random key and IV every time). Only the scrambled version goes to IPFS.
2. IPFS gives back a **CID**: a fingerprint-address of the exact bytes. Same bytes always give the same CID. Different bytes give a different CID.
3. When we fetch a file later, we **recompute the CID ourselves** and refuse the data if it doesn't match. A faulty or dishonest IPFS node can't swap in different data without being noticed.
4. The IPFS node never sees the original file. The test searches the node's storage to prove it.
5. Deleting from IPFS is only **local and best effort**. This is why real erasure must come from destroying the key.

## Files
| File | Role |
|---|---|
| `vault.mjs` | Browser-side code: encrypt, decrypt, talk to IPFS, work out and check CIDs |
| `test_ipfs.mjs` | 13 checks. It starts its own temporary IPFS node and shuts it down at the end |

## How to run
You need Node.js (tested on Node 22; the project says 20 or newer. If you see an odd error on 20, try 22). In the terminal, inside `spikes/ipfs`:

```
npm install
npm test
```

- **The first run downloads the IPFS program (Kubo), about 120 MB**, so you need internet that one time.
- The test node runs in **offline mode** and only talks to your own computer. If Windows shows a firewall question for `ipfs.exe`, you can click Cancel (don't allow). The test still works.
- You should see 13 lines starting with `PASS`, then `ALL TESTS PASSED`.

## What the tests show
| Check | Why it matters |
|---|---|
| Full round trip (encrypt, upload, fetch, verify, decrypt) | The whole file pipeline works |
| Plaintext is NOT in the node's stored blocks, and an unencrypted control file IS | Proves the search works, so "not found" means something |
| Same file encrypted twice gives a different IV and a different CID | Nobody can tell that two people uploaded the same file |
| Our CID calculation equals Kubo's, for sizes from 1 byte to 5 MB, including multi-chunk files | We can safely verify the node's answers |
| A node that changes the data is rejected (`CID_MISMATCH`) | Protects against a faulty or dishonest node |
| 1 changed bit, the wrong key, or the wrong asset ID is rejected by AES-GCM | The file is tamper-proof and tied to its asset ID |
| Unpin alone does **not** delete; garbage collection does; pinned files survive | Shows how IPFS "deletion" really works |

## Speed (cloud sandbox, 5 MB file)
Encrypt about 5 ms, upload about 34 ms, fetch and verify about 42 ms, decrypt about 5 ms. Measure again on your machine for the report.

## Notes for the Next.js step (Member D)
- **Never expose Kubo's API (port 5001) to the internet or to other users.** It gives full control of the node. For the MVP, I'd have the browser send the **ciphertext to the FastAPI backend**, which talks to Kubo. That's one of the open questions in the interface contract.
- If you do call Kubo straight from the browser during local testing, it needs CORS settings, for example `ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["http://localhost:3000"]'`. Check Kubo's docs for the exact settings.
- For the demo, run your own node with `ipfs daemon --offline`. It keeps everything on your machine.
- The IV is not secret. Store it next to the CID in the asset metadata (the `iv` field in the contract).

## Limits to state in the report
- **A CID is public and permanent.** Never put names or other personal details in file names or contents without encrypting them.
- **File size leaks.** The ciphertext is the plaintext size plus 16 bytes. Padding files to fixed sizes would hide it (future work).
- **Unpin and garbage collection only affect your own node.** On a real network, other nodes may keep copies. Real erasure means destroying the key (crypto-shredding), and then the leftover ciphertext is useless.
- Run in **offline mode** for the demo. Joining the public IPFS network was not tested.
- This ran in Node, not yet in a real browser page (same WebCrypto and `fetch` code, but the Next.js test will confirm).
