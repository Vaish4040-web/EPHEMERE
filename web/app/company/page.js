import Link from "next/link";
import StatusPanel from "../../components/StatusPanel";

export const metadata = { title: "Company - EPHEMERE" };

export default function CompanyPage() {
  return (
    <>
      <p><Link href="/">&larr; Home</Link></p>
      <h1>Company portal</h1>
      <p>Signed in as <strong>QuickDeliver</strong> (demo account). You only ever receive the one field you asked for.</p>
      <StatusPanel />
      <div className="card"><strong>Ask for data</strong><p className="note">Coming in step M3: send a request.</p></div>
      <div className="card"><strong>Your requests</strong><p className="note">Coming in step M3 and M4: results, refusals and expiry.</p></div>
    </>
  );
}
