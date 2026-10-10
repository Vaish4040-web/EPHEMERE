import Link from "next/link";

export default function Home() {
  return (
    <>
      <h1>EPHEMERE</h1>
      <p>Zero-trust privacy middleware for DPDP Act compliance.</p>
      <div className="card">
        <strong>Asha's vault</strong>
        <p>Where a person keeps encrypted files and decides who may see what.</p>
        <Link href="/vault">Open the vault</Link>
      </div>
      <div className="card">
        <strong>Company portal</strong>
        <p>Where QuickDeliver asks for data and receives only what was approved.</p>
        <Link href="/company">Open the company portal</Link>
      </div>
      <div className="card">
        <strong>Browser self-test</strong>
        <p>Checks that file encryption, secure sharing and zero-knowledge proofs all work inside this browser.</p>
        <Link href="/lab">Open the self-test page</Link>
      </div>
    </>
  );
}
