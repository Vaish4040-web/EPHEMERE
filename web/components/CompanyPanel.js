"use client";

import { useCallback, useEffect, useState } from "react";
import { askForData, getData, getPolicy, listOrgRequests, ORG_ACCOUNTS } from "../lib/requests";

const FIELDS = { address: "address", name: "name", phone: "phone number", blood_group: "blood group" };
const DURATIONS = [[30, "30 seconds"], [60, "1 minute"], [600, "10 minutes"], [3600, "1 hour"]];

// The company's side: ask for ONE field for a stated purpose, then collect it once the person has approved.
export default function CompanyPanel() {
  const [account, setAccount] = useState("quickdeliver");
  const [policy, setPolicy] = useState(null);
  const [form, setForm] = useState({ subject: "asha", field: "address", purpose: "DELIVERY", durationSec: 600 });
  const [requests, setRequests] = useState([]);
  const [results, setResults] = useState({});   // requestId -> {value} or {error}
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try { setRequests(await listOrgRequests(account)); setError(""); }
    catch (e) { setError(e.message); }
  }, [account]);

  useEffect(() => { getPolicy().then(setPolicy).catch(() => {}); }, []);
  useEffect(() => {
    setResults({}); refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  async function send() {
    setBusy(true); setError("");
    try { await askForData(account, form); await refresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function collect(id) {
    try { const r = await getData(account, id); setResults((x) => ({ ...x, [id]: { value: r.value, field: r.field } })); }
    catch (e) { setResults((x) => ({ ...x, [id]: { error: e.message } })); }
  }

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: k === "durationSec" ? Number(e.target.value) : e.target.value }));
  const purposes = policy?.purposes ?? [];
  const label = (p) => purposes.find((x) => x.code === p)?.label ?? p;

  return (
    <>
      <div className="card">
        <label className="field">Signed in as (demo account)
          <select id="account" value={account} onChange={(e) => setAccount(e.target.value)}>
            {ORG_ACCOUNTS.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </label>
      </div>

      <div className="card" id="ask-card">
        <strong>Ask for data</strong>
        <p className="note">Name the person, ONE field, a purpose and how long you need it. The person decides. You will only ever receive that one field.</p>
        <div className="grid2">
          <label className="field">Person
            <select id="f-subject" value={form.subject} onChange={set("subject")}>
              <option value="asha">Asha</option><option value="ravi">Ravi</option>
            </select>
          </label>
          <label className="field">Purpose
            <select id="f-purpose" value={form.purpose} onChange={set("purpose")}>
              {purposes.map((p) => <option key={p.code} value={p.code}>{p.label}</option>)}
            </select>
          </label>
          <label className="field">What you need
            <select id="f-field" value={form.field} onChange={set("field")}>
              {Object.entries(FIELDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label className="field">For how long
            <select id="f-duration" value={form.durationSec} onChange={set("durationSec")}>
              {DURATIONS.map(([s, t]) => <option key={s} value={s}>{t}</option>)}
            </select>
          </label>
        </div>
        <div className="btnrow"><button id="send-request" onClick={send} disabled={busy || !policy}>Send request</button></div>
        <p className="note">Each purpose only allows certain fields (for example delivery allows address, name and phone). Try asking for something it does not allow.</p>
        {error && <p className="err" id="org-error">{error}</p>}
      </div>

      <div className="card" id="org-requests">
        <strong>Your requests</strong>
        {requests.length === 0 && <p className="note">No requests yet.</p>}
        {requests.map((r) => {
          const res = results[r.requestId];
          return (
            <div className="reqrow org-request" key={r.requestId} data-status={r.status} data-request={r.requestId}>
              <div>
                {FIELDS[r.field] ?? r.field} of <strong>{r.subject}</strong>, for {label(r.purpose)}
                <span className={`pill ${r.status}`}>{r.status}</span>
              </div>
              <div className="mono">{r.durationSec >= 60 ? `${r.durationSec / 60} min` : `${r.durationSec} s`} requested</div>
              {r.status === "approved" && <div className="btnrow"><button className="get-data-btn" onClick={() => collect(r.requestId)}>Get the data</button></div>}
              {r.status === "pending" && <p className="note">Waiting for {r.subject} to decide...</p>}
              {r.status === "denied" && <p className="note">{r.subject} said no.</p>}
              {(r.status === "expired" || r.status === "revoked") && <p className="note">This permission has ended.</p>}
              {res?.value !== undefined && <div className="value data-result">{FIELDS[res.field] ?? res.field}: {String(res.value)}</div>}
              {res?.error && <p className="err data-error">{res.error}</p>}
            </div>
          );
        })}
      </div>
    </>
  );
}
