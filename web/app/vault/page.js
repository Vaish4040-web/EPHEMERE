import Link from "next/link";
import StatusPanel from "../../components/StatusPanel";

export const metadata = { title: "Vault - EPHEMERE" };

export default function VaultPage() {
  return (
    <>
      <p><Link href="/">&larr; Home</Link></p>
      <h1>Vault</h1>
      <p>Signed in as <strong>Asha</strong> (demo account). Your files are encrypted in this browser before they leave it.</p>
      <StatusPanel />
      <div className="card"><strong>Your files</strong><p className="note">Coming in step M2: upload a file.</p></div>
      <div className="card"><strong>Requests waiting for you</strong><p className="note">Coming in step M3: approve or deny.</p></div>
      <div className="card"><strong>Your history</strong><p className="note">Coming in step M4 and M6: see and verify every decision.</p></div>
    </>
  );
}
