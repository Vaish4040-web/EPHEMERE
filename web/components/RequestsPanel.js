"use client";

import { useCallback, useEffect, useState } from "react";
import { denyRequest, approveRequest, listUserRequests } from "../lib/requests";
import { listFiles } from "../lib/vault";

const FIELDS = { address: "address", name: "name", phone: "phone number", blood_group: "blood group" };
const PURPOSES = { DELIVERY: "delivery", KYC: "an identity check", CONSULTATION: "a medical consultation" };
const length = (s) => (s >= 3600 ? `${s / 3600} hour` : s >= 60 ? `${s / 60} minute${s >= 120 ? "s" : ""}` : `${s} seconds`);

// Asha's inbox: who is asking for what, why and for how long. She decides, and chooses which file to use.
export default function RequestsPanel() {
  const [requests, setRequests] = useState([]);
  const [files, setFiles] = useState([]);
  const [pick, setPick] = useState({});          // requestId -> assetId
  const [problems, setProblems] = useState({});
  const [busy, setBusy] = useState({});

  const refresh = useCallback(async () => {
    try { setRequests(await listUserRequests()); setFiles(await listFiles()); }
    catch { /* the status panel already says when the gateway is down */ }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh]);

  async function decide(id, action) {
    setBusy((b) => ({ ...b, [id]: true })); setProblems((p) => ({ ...p, [id]: "" }));
    try {
      if (action === "approve") await approveRequest(id, pick[id] ?? files[0]?.assetId);
      else await denyRequest(id);
      await refresh();
    } catch (e) {
      setProblems((p) => ({ ...p, [id]: e.code === "BAD_KFRAG" ? `${e.message} Choose a file that was uploaded from this browser.` : e.message }));
    } finally { setBusy((b) => ({ ...b, [id]: false })); }
  }

  return (
    <div className="card" id="requests-card">
      <strong>Requests for your data</strong>
      {requests.length === 0 && <p className="note" id="no-requests">Nothing waiting.</p>}
      {requests.map((r) => (
        <div className="reqrow incoming" key={r.requestId} data-status={r.status} data-request={r.requestId}>
          <div>
            <strong>{r.org}</strong> wants your <strong>{FIELDS[r.field] ?? r.field}</strong> for {PURPOSES[r.purpose] ?? r.purpose},
            for {length(r.durationSec)}.
            <span className={`pill ${r.status}`}>{r.status}</span>
          </div>
          {r.status === "pending" && (
            <>
              {files.length === 0 && <p className="note">Upload a file first, so there is something to share from.</p>}
              {files.length > 0 && (
                <div className="btnrow">
                  <label className="field">Share from this file
                    <select className="pick-file" value={pick[r.requestId] ?? files[0].assetId} onChange={(e) => setPick((p) => ({ ...p, [r.requestId]: e.target.value }))}>
                      {files.map((f) => <option key={f.assetId} value={f.assetId}>{f.label}</option>)}
                    </select>
                  </label>
                  <button className="approve-btn" onClick={() => decide(r.requestId, "approve")} disabled={busy[r.requestId]}>Approve</button>
                  <button className="secondary deny-btn" onClick={() => decide(r.requestId, "deny")} disabled={busy[r.requestId]}>Deny</button>
                </div>
              )}
              <p className="note">{r.org} will only receive this one field, never the whole file, and only until the time is up.</p>
            </>
          )}
          {r.status === "approved" && r.expiresAt && <p className="note">Allowed until {new Date(r.expiresAt * 1000).toLocaleTimeString()}.</p>}
          {problems[r.requestId] && <p className="err req-error">{problems[r.requestId]}</p>}
        </div>
      ))}
    </div>
  );
}
