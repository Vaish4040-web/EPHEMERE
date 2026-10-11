"use client";

import { useCallback, useEffect, useState } from "react";
import { getOwnerKeys } from "../lib/keys";
import { listFiles, openFile, sampleProfile, uploadFile } from "../lib/vault";

const kb = (n) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);

// Asha's keys, upload and files. Everything is encrypted in THIS browser before anything is sent.
export default function FilesPanel() {
  const [keys, setKeys] = useState(null);
  const [files, setFiles] = useState([]);
  const [label, setLabel] = useState("profile.json");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [opened, setOpened] = useState({});     // assetId -> result of opening
  const [problems, setProblems] = useState({}); // assetId -> message
  const [showStored, setShowStored] = useState({});

  const refresh = useCallback(async () => {
    try { setFiles(await listFiles()); setError(""); }
    catch (e) { setError(e.message); }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const k = await getOwnerKeys();
        setKeys({ fingerprint: k.fingerprint, created: k.created });
      } catch (e) { setError(`Could not prepare your keys: ${e.message}`); }
      await refresh();
    })();
  }, [refresh]);

  async function upload(bytes, name) {
    setBusy(true); setError("");
    try { await uploadFile({ label: name, bytes }); await refresh(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function onPick(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    await upload(new Uint8Array(await f.arrayBuffer()), label);
    e.target.value = "";
  }

  async function open(id) {
    setProblems((p) => ({ ...p, [id]: "" }));
    try { const r = await openFile(id); setOpened((o) => ({ ...o, [id]: r })); }
    catch (e) { setOpened((o) => ({ ...o, [id]: undefined })); setProblems((p) => ({ ...p, [id]: e.message })); }
  }

  return (
    <>
      <div className="card" id="keys-card" data-ready={keys ? "true" : "false"}>
        <strong>Your keys</strong>
        {!keys && <p className="note">Preparing...</p>}
        {keys && (
          <>
            <p className="note" id="key-fingerprint" data-created={String(keys.created)}>
              Key fingerprint: {keys.fingerprint} {keys.created ? "(new keys were just created in this browser)" : "(found in this browser)"}
            </p>
            <p className="note">Your secret keys stay in this browser and are never sent anywhere. If you clear your browser data you lose access to your files (there is no key backup yet).</p>
          </>
        )}
      </div>

      <div className="card">
        <strong>Upload a file</strong>
        <p className="note">The file is encrypted here, in your browser. Only the scrambled version is sent. The label below is <em>not</em> encrypted, so do not put personal details in it.</p>
        <div className="btnrow">
          <input type="text" id="label" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={40} aria-label="Label" />
          <button id="upload-sample" onClick={() => upload(sampleProfile(), label)} disabled={busy || !keys}>
            {busy ? "Working..." : "Upload a sample profile"}
          </button>
          <input type="file" id="file-input" onChange={onPick} disabled={busy || !keys} style={{ width: "auto" }} />
        </div>
        {error && <p className="err" id="error">{error}</p>}
      </div>

      <div className="card" id="files-card">
        <strong>Your files</strong>
        {files.length === 0 && <p className="note" id="no-files">No files yet.</p>}
        {files.map((f) => {
          const r = opened[f.assetId];
          return (
            <div className="filerow file-row" key={f.assetId} data-asset={f.assetId}>
              <div className="filehead">
                <span>{f.label} <span className="mono">({kb(f.sizeBytes)})</span></span>
                <span className="btnrow" style={{ margin: 0 }}>
                  <button className="open-btn" onClick={() => open(f.assetId)}>Open</button>
                  <button className="secondary stored-btn" onClick={() => { setShowStored((s) => ({ ...s, [f.assetId]: !s[f.assetId] })); if (!r) open(f.assetId); }}>
                    What IPFS holds
                  </button>
                </span>
              </div>
              <div className="mono" title={f.cid}>CID: {f.cid}</div>
              {problems[f.assetId] && <p className="err file-problem">{problems[f.assetId]}</p>}
              {r && (
                <>
                  <div className="ok" id="cid-verified">CID verified: the stored bytes match their address</div>
                  <pre className="block opened-text" id="opened-text">{r.text}</pre>
                </>
              )}
              {showStored[f.assetId] && r && (
                <>
                  <p className="note">This is everything IPFS holds for this file ({r.storedBytes} scrambled bytes; first 48 shown):</p>
                  <pre className="block stored-hex" id="stored-hex">{r.storedPreviewHex}</pre>
                </>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
