import Link from "next/link";
import CompanyPanel from "../../components/CompanyPanel";
import StatusPanel from "../../components/StatusPanel";

export const metadata = { title: "Company - EPHEMERE" };

export default function CompanyPage() {
  return (
    <>
      <p><Link href="/">&larr; Home</Link></p>
      <h1>Company portal</h1>
      <p>You only ever receive the one field you asked for, and only if the person approves.</p>
      <StatusPanel />
      <CompanyPanel />
    </>
  );
}
