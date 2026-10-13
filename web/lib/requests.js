// Requests between a company and a person. The browser only talks to the gateway.
import { fromB64, toB64 } from "./bytes";
import { getOwnerKeys } from "./keys";
import { makeKfrags } from "./pre";
import { apiJson } from "./session";

export const ORG_ACCOUNTS = [{ id: "quickdeliver", name: "QuickDeliver" }, { id: "freshmart", name: "FreshMart" }];

export async function getPolicy() {
  return (await fetch("/api/policy")).json();
}

// ---------- the company ----------
export const askForData = (account, body) =>
  apiJson("/api/org/requests", { account, method: "POST", body: JSON.stringify(body) });
export const listOrgRequests = async (account) => (await apiJson("/api/org/requests", { account })).requests;
export const getData = (account, requestId) => apiJson(`/api/org/requests/${requestId}/access`, { account, method: "POST" });

// ---------- the person ----------
export const listUserRequests = async () => (await apiJson("/api/user/requests")).requests;
export const denyRequest = (requestId) => apiJson(`/api/user/requests/${requestId}/deny`, { method: "POST" });

// Approve: THIS browser makes the permission pieces (kfrags) for the access service. The secret key never leaves it.
export async function approveRequest(requestId, assetId) {
  const { U, owner } = await getOwnerKeys();
  const { publicKey } = await apiJson("/api/access-key");
  const accessPk = U.PublicKey.fromCompressedBytes(fromB64(publicKey));
  const kfrags = makeKfrags(U, owner, accessPk, 1, 1).map((k) => toB64(k.toBytes()));
  return apiJson(`/api/user/requests/${requestId}/approve`, { method: "POST", body: JSON.stringify({ assetId, kfrags }) });
}
