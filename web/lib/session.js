// DEMO sign-in: no passwords (not real security). The token lives in sessionStorage, so it is forgotten when the tab closes.
const KEY = "ephemere.sessions.v2";   // one token per demo account

export class ApiProblem extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

const readAll = () => { try { return JSON.parse(sessionStorage.getItem(KEY) ?? "{}"); } catch { return {}; } };

async function signIn(account) {
  const r = await fetch("/api/demo/login", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account }),
  });
  if (!r.ok) throw new ApiProblem(r.status, "SIGN_IN_FAILED", "Could not sign in. Is everything running? (python demo/run_all.py)");
  const body = await r.json();
  sessionStorage.setItem(KEY, JSON.stringify({ ...readAll(), [account]: body.token }));
  return body.token;
}

async function token(account) {
  return readAll()[account] || signIn(account);
}

// Calls the gateway as the given demo account. Signs in again once if the token was forgotten (for example after a restart).
export async function api(path, { account = "asha", ...options } = {}) {
  const call = async (t) => fetch(path, {
    ...options,
    headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers, Authorization: `Bearer ${t}` },
  });
  let res = await call(await token(account));
  if (res.status === 401) res = await call(await signIn(account));
  return res;
}

export async function apiJson(path, options) {
  const res = await api(path, options);
  if (!res.ok) {
    let err = { code: "ERROR", message: `The server answered ${res.status}.` };
    try { err = (await res.json()).error ?? err; } catch { /* keep the generic message */ }
    throw new ApiProblem(res.status, err.code, err.message);
  }
  return res.json();
}
