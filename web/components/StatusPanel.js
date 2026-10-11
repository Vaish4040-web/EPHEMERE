"use client";

import { useEffect, useState } from "react";

const LABELS = {
  gateway: "Gateway",
  proxy: "Proxy (holds key pieces)",
  access: "Access service (opens files in memory)",
  ipfs: "IPFS (stores encrypted files)",
  database: "Database",
};

// Shows whether every part of the system is running. Refreshes every 5 seconds.
export default function StatusPanel() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const r = await fetch("/api/status");
        if (!r.ok) throw new Error(`status ${r.status}`);
        const body = await r.json();
        if (!stop) { setStatus(body); setError(""); }
      } catch (e) {
        if (!stop) { setStatus(null); setError("The gateway is not reachable. Start everything with: python demo/run_all.py"); }
      }
    }
    load();
    const t = setInterval(load, 5000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  return (
    <div className="card" id="status-panel" data-all-ok={status ? String(status.allOk) : "unknown"}>
      <strong>System status</strong>
      {error && <p className="note">{error}</p>}
      {!error && !status && <p className="note">Checking...</p>}
      {status && Object.keys(LABELS).map((k) => (
        <div className="row" key={k} data-service={k} data-ok={String(status[k]?.ok)}>
          <div className={`badge ${status[k]?.ok ? "PASS" : "FAIL"}`}>{status[k]?.ok ? "UP" : "DOWN"}</div>
          <div>
            <div>{LABELS[k]}</div>
            <div className="note">{status[k]?.detail}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
