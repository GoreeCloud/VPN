import React, { useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Peer = { id: string; name: string; public_key: string; address: string; approved_at?: string | null; revoked_at?: string | null };
type PeerResponse = { peers: Peer[] };

async function fetchJSON<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  if (!token || token.length < 32) throw new Error("Missing access credentials");
  const response = await fetch(path, {
    ...init,
    redirect: "error",
    cache: "no-store",
    credentials: "omit",
    headers: {
      "Authorization": "Bearer " + token,
      "Accept": "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {})
    }
  });
  if (!response.ok) throw new Error("Management request returned HTTP " + response.status);
  const len = Number(response.headers.get("content-length") || 0);
  if (len > 1_000_000) throw new Error("Management response too large");
  return response.json() as Promise<T>;
}

function App() {
  // No localStorage, cookies, sessionStorage, URL parameter or service worker.
  const [credential, setCredential] = useState("");
  const [token, setToken] = useState("");
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const fetchPeers = useCallback(async (activeToken: string) => {
    const result = await fetchJSON<PeerResponse>("/v1/peers", activeToken);
    if (!Array.isArray(result.peers)) throw new Error("Unexpected peer API");
    setPeers(result.peers);
  }, []);
  async function login(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const candidate = credential;
    setCredential(""); setError(""); setBusy(true);
    try {
      const result = await fetchJSON<{ tunnel_operational: boolean }>("/v1/info", candidate);
      if (result.tunnel_operational !== false) throw new Error("Unexpected control-plane contract");
      await fetchPeers(candidate);
      setToken(candidate);
      setNotice("Control plane connected. No tunnel has been verified.");
    } catch {
      setToken("");
      setError("Connection rejected. Verify the administrator credential and local service.");
    } finally { setBusy(false); }
  }
  function logout() {
    setToken(""); setCredential(""); setPeers([]); setNotice("Access credential cleared from memory.");
    setError("");
  }
  async function refresh() {
    setError(""); setBusy(true);
    try { await fetchPeers(token); }
    catch { setError("Unable to refresh management inventory."); }
    finally { setBusy(false); }
  }
  async function enroll(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!window.confirm("Enroll this device's PUBLIC key? This does not activate a VPN tunnel.")) return;
    setBusy(true); setError("");
    try {
      await fetchJSON("/v1/peers", token, {
        method: "POST", body: JSON.stringify({name: name.trim(), public_key: publicKey.trim()})
      });
      await fetchPeers(token);
      setName(""); setPublicKey("");
      setNotice("Device enrolled as pending. An administrator must approve it before gateway export; a separate gateway apply is still required.");
    } catch {
      setError("Enrollment failed. Check the public key, name and duplicate records.");
    } finally { setBusy(false); }
  }
  async function approve(peer: Peer) {
    if (!window.confirm("Approve " + peer.name + " for future gateway configuration exports? Review this public key and device owner first. This does NOT change a running VPN gateway.")) return;
    setBusy(true); setError("");
    try {
      await fetchJSON("/v1/peers/" + encodeURIComponent(peer.id) + "/approve", token, { method: "POST" });
      await fetchPeers(token);
      setNotice("Identity approved. A reviewed gateway export and explicit apply are still required for packet access.");
    } catch { setError("Approval failed. Verify authorization and the peer state."); }
    finally { setBusy(false); }
  }
  async function revoke(peer: Peer) {
    if (!window.confirm("Revoke " + peer.name + " in the registry? This does NOT remove a live WireGuard peer until the gateway is updated.")) return;
    setBusy(true); setError("");
    try {
      await fetchJSON("/v1/peers/" + encodeURIComponent(peer.id) + "/revoke", token, { method: "POST" });
      await fetchPeers(token);
      setNotice("Registration revoked. Apply the new gateway configuration to enforce removal.");
    } catch { setError("Revocation failed. Verify the management connection."); }
    finally { setBusy(false); }
  }
  const approved = peers.filter(x => x.approved_at && !x.revoked_at);
  const pending = peers.filter(x => !x.approved_at && !x.revoked_at);
  const revoked = peers.filter(x => x.revoked_at);
  return <main className="shell">
    <header className="masthead">
      <div className="brand"><div className="brand-icon" aria-hidden="true">◈</div>
        <div><strong>GoreeCloud</strong><span>VPN · Private network</span></div></div>
      {token ? <button className="secondary" onClick={logout} disabled={busy}>Sign out</button> : <span className="top-state">LOCAL ADMIN</span>}
    </header>
    {!token ? <section className="login surface" aria-labelledby="login-title">
        <span className="eyebrow">PRIVATE ACCESS</span>
        <h1 id="login-title">Your network.<br/><em>Your rules.</em></h1>
        <p>Sign in with the local administrator token. Nothing is saved in browser storage or sent to third parties.</p>
        <form onSubmit={login}>
          <label htmlFor="token">Administrator token</label>
          <input id="token" type="password" minLength={32} required autoComplete="off"
            value={credential} onChange={e => setCredential(e.target.value)} spellCheck={false} />
          <button className="primary" type="submit" disabled={busy}>{busy ? "Connecting…" : "Open console"}</button>
        </form>
        {error && <p role="alert" className="error">{error}</p>}
      </section> :
      <>
        <section className="hero"><span className="eyebrow">NETWORK CONTROL</span>
          <h1>Connected to your<br/><em>control plane.</em></h1>
          <p>Review registered identities and manage their enrollment. Device enrollment defaults to pending; only explicitly approved identities can enter future gateway configuration exports. Actual packet access requires separate reviewed gateway policy and application.</p>
        </section>
        <section className="stats" aria-label="Network inventory summary">
          <article className="surface"><span>Approved</span><strong>{approved.length}</strong><small>Eligible for a reviewed gateway export</small></article>
          <article className="surface"><span>Pending review</span><strong>{pending.length}</strong><small>Not eligible for gateway export</small></article>
          <article className="surface"><span>Data plane</span><strong className="state-text">Unverified</strong><small>No live tunnel assertion</small></article>
        </section>
        {error && <p role="alert" className="error">{error}</p>}
        {notice && <p role="status" className="notice">{notice}</p>}
        <div className="columns">
          <section className="surface panel" aria-labelledby="peers-title">
            <div className="heading"><div><span className="eyebrow">PEER INVENTORY</span>
              <h2 id="peers-title">Device enrollment</h2></div>
              <button className="secondary" onClick={refresh} disabled={busy}>Refresh</button>
            </div>
            {peers.length === 0 ? <p className="empty">No devices enrolled. New devices require explicit approval.</p> :
              <ul className="peer-list">{peers.map(p => <li key={p.id}>
                <div className="avatar" aria-hidden="true">⌁</div>
                <div className="peer-main"><strong>{p.name}</strong>
                  <code title={p.public_key}>{p.public_key.slice(0, 10)}…{p.public_key.slice(-6)}</code>
                  <small>{p.address}</small></div>
                {p.revoked_at ? <span className="pill revoked">Revoked</span> :
                  <div className="peer-actions">
                    {p.approved_at ? <span className="pill">Approved</span> :
                      <button className="secondary" disabled={busy} onClick={() => approve(p)}>Approve</button>}
                    <button className="revoke" disabled={busy} onClick={() => revoke(p)}>Revoke</button>
                  </div>}
              </li>)}</ul>}
          </section>
          <section className="surface panel" aria-labelledby="enroll-title">
            <span className="eyebrow">ONBOARDING</span><h2 id="enroll-title">Request device enrollment</h2>
            <p>Generate a private/public key pair on the device. Paste its public key only.</p>
            <form onSubmit={enroll}>
              <label htmlFor="device-name">Device name</label>
              <input id="device-name" required maxLength={64} placeholder="Example: Family laptop"
                value={name} onChange={e => setName(e.target.value)} />
              <label htmlFor="public-key">WireGuard public key</label>
              <textarea id="public-key" required rows={3} spellCheck={false} placeholder="Canonical base64 public key"
                value={publicKey} onChange={e => setPublicKey(e.target.value)} />
              <button className="primary" type="submit" disabled={busy}>Enroll peer</button>
            </form>
            <p className="footnote">Enrollment does not authorize a device. An administrator must approve its public key separately, and every gateway change must be reviewed and explicitly applied.</p>
          </section>
        </div>
      </>}
    <footer>GoreeCloud VPN · Development preview · {revoked.length} revoked identities · No third-party telemetry or account tracking</footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
