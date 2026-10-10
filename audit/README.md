# Audit log spike (Member C): a diary nobody can secretly rewrite

**What this proves, in simple words**

Every decision (allow, deny, grant, revoke) is written to a log. Our promise is not "nobody can change the file". Our promise is: **if anyone changes history, it can be detected.** The tests prove this with real attacks.

## How it works (three layers)
1. **Hash chain.** Each event stores the fingerprint (hash) of the event before it. Change or delete one event in the middle, and everything after it stops matching.
2. **Merkle root.** One short fingerprint that summarizes the whole log. It also lets a user prove "my event is in the log" using only about 10 small hashes, without seeing anyone else's events.
3. **Signed checkpoints.** Now and then the operator signs "the log has N events and root R". A user (or auditor) keeps these. If the log is ever rewritten, it can no longer prove it extends the saved checkpoint, and the operator's own signature is the proof of cheating.

**No personal data can enter the log.** The code only accepts IDs, a fixed list of event types, `allow`/`deny`/`n/a`, and short UPPER_CASE reason codes. Free text and emails are rejected.

## Files
| File | Role |
|---|---|
| `merkle.py` | Tree maths: root, inclusion proof, consistency proof (the same design Certificate Transparency uses) |
| `auditlog.py` | The log: rules for events, file storage, checkpoints, and stand-alone `verify_*` functions anyone can run |
| `test_audit.py` | 29 checks |

## How to run (Windows)
Python 3.11, same as the rest of the project. In the terminal, inside the `audit` folder:

```
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python test_audit.py
```

You should see 29 lines starting with `PASS` and then `ALL TESTS PASSED`. Two `INFO` lines show speed numbers for your report.

## What the tests cover
- The tree maths matches the **published official test vectors** (RFC 6962), and every position and size from 1 to 40 is checked for inclusion and consistency, including wrong answers being rejected.
- **Attacks that are detected:** editing an event, deleting one in the middle, swapping two.
- **Two honest limits, shown on purpose:**
  1. Cutting off the **last** events leaves a file that still verifies by itself. Only a person holding an **older checkpoint** can notice.
  2. An operator who rebuilds the **whole** log with a changed event can make a file that verifies by itself. But it cannot prove it extends the user's old checkpoint.
  
  **So checkpoints must be kept by someone other than the operator** (the user's browser, an auditor, or a published page). This is the honest answer to "is it as good as a blockchain?": it detects tampering, but only if someone outside holds a checkpoint.
- Single-event proofs: the user's own copy of an event matches, an altered copy does not.
- Signed checkpoints: a changed size or the wrong key is rejected.

## Test results (cloud sandbox)
About 0.2 ms per append (each one flushed to disk), a proof for a 2000-event log needs 11 hashes and verifies in about 1 ms. Measure again on your machine for the report.

## Limits for the report
- One process writes the file. Real deployment needs a lock or a database.
- Checkpoints are only as good as who keeps them. Decide who stores them (see threat model T6).
- The Ed25519 key for signing is created in the test. In the project it must be stored safely and never committed.
