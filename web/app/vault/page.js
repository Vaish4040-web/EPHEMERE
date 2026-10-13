import Link from "next/link";
import FilesPanel from "../../components/FilesPanel";
import RequestsPanel from "../../components/RequestsPanel";
import StatusPanel from "../../components/StatusPanel";

export const metadata = { title: "Vault - EPHEMERE" };

export default function VaultPage() {
  return (
    <>
      <p><Link href="/">&larr; Home</Link></p>
      <h1>Vault</h1>
      <p>Signed in as <strong>Asha</strong> (demo account). Your files are encrypted in this browser before they leave it.</p>
      <StatusPanel />
      <FilesPanel />
      <RequestsPanel />
      <div className="card"><strong>Your history</strong><p className="note">Coming in steps M4 and M6: revoke a permission, and see and verify every decision.</p></div>
    </>
  );
}
