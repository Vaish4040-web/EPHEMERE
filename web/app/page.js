import Link from "next/link";

export default function Home() {
  return (
    <>
      <h1>EPHEMERE</h1>
      <p>Zero-trust privacy middleware for DPDP Act compliance. The real vault and company portals will live here.</p>
      <div className="card">
        <strong>Browser self-test</strong>
        <p>Checks that file encryption, secure sharing and zero-knowledge proofs all work inside this browser.</p>
        <Link href="/lab">Open the self-test page</Link>
      </div>
    </>
  );
}
