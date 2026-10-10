"use client";

import { useState } from "react";
import { createShareBundle, runAllChecks } from "../../lib/lab";

export default function LabPage() {
  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [running, setRunning] = useState(false);

  const [bobPk, setBobPk] = useState("");
  const [bundle, setBundle] = useState("");
  const [bundleErr, setBundleErr] = useState("");

  async function start() {
    setRunning(true); setSummary(null); setRows([]);
    const { results, summary } = await runAllChecks(setRows);
    setSummary(summary); setRunning(false);
    window.__LAB__ = { done: true, results, summary };   // lets automated tests read the outcome
  }

  async function makeBundle() {
    setBundleErr(""); setBundle("");
    try { setBundle(JSON.stringify(await createShareBundle(bobPk), null, 2)); }
    catch (e) { setBundleErr(String(e?.message ?? e)); }
  }

  const groups = [...new Set(rows.map((r) => r.group))];

  return (
    <>
      <h1>Browser self-test</h1>
      <p>
        Runs every building block inside <em>this</em> browser: file encryption, secure sharing (Umbral, WebAssembly) and
        the zero-knowledge age proof. Nothing is sent anywhere.
      </p>
      <button id="run" onClick={start} disabled={running}>{running ? "Running..." : "Run all checks"}</button>

      {summary && (
        <div className="summary" id="summary" data-done="true">
          {summary.fail === 0 ? "All checks passed" : `${summary.fail} check(s) failed`} &nbsp;·&nbsp; {summary.pass} passed, {summary.fail} failed, {summary.skip} skipped
        </div>
      )}

      {groups.map((g) => (
        <section key={g}>
          <h2>{g}</h2>
          <div className="card">
            {rows.filter((r) => r.group === g).map((r, i) => (
              <div className="row" key={i}>
                <div className={`badge ${r.status}`}>{r.status}</div>
                <div>
                  <div>{r.name}</div>
                  {r.note && <div className="note">{r.note}</div>}
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}

      <h2>Optional: test with the Python server side</h2>
      <p>
        Run <code>python make_bob.py</code> in <code>spikes/pre</code>, paste the public key it prints here, create the bundle,
        save it as <code>bundle.json</code>, then run <code>python verify_bundle.py bundle.json</code>.
      </p>
      <div className="card">
        <input id="bobpk" placeholder="Access service public key (base64)" value={bobPk} onChange={(e) => setBobPk(e.target.value)} />
        <p />
        <button id="bundle-btn" onClick={makeBundle} disabled={!bobPk.trim()}>Create share bundle</button>
        {bundleErr && <p className="note">Error: {bundleErr}</p>}
        {bundle && <><p /><textarea id="bundle" readOnly value={bundle} /></>}
      </div>
    </>
  );
}
