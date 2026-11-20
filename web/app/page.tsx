"use client";
import { FormEvent, useCallback, useEffect, useState } from "react";

type Peer = {
  id: string; name: string; public_key: string; address: string;
  created_at: number; revoked_at: number | null
};

function terseKey(key: string) {
  return key.slice(0, 9) + "…" + key.slice(-7);
}
export default function Page() {
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [peers, setPeers] = useState<Peer[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/peers", { cache: "no-store" });
      if (res.status === 401) { setSignedIn(false); return; }
      if (!res.ok) throw new Error("Management service unavailable");
      const data = await res.json() as { peers: Peer[] };
      setPeers(data.peers);
      setSignedIn(true);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load peers");
      setSignedIn(true);
    }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);

  async function signIn(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/session", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      if (!res.ok) throw new Error("Invalid credentials or access unavailable");
      setPassword("");
      await refresh();
    } catch (err) { setError(String(err instanceof Error ? err.message : err)); }
    finally { setBusy(false); }
  }
  async function logout() {
    await fetch("/api/session", { method: "DELETE" });
    setPeers([]); setSignedIn(false); setNotice("");
  }
  async function enroll(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const res = await fetch("/api/peers", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), public_key: key.trim() })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Unable to enroll peer");
      setName(""); setKey("");
      setNotice("Peer added to inventory. Render and apply the server configuration separately.");
      await refresh();
    } catch (err) { setError(String(err instanceof Error ? err.message : err)); }
    finally { setBusy(false); }
  }
  async function revoke(peer: Peer) {
    if (!window.confirm("Revoke " + peer.name + "? You must also apply the updated server configuration.")) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const res = await fetch("/api/peers/" + peer.id, { method: "DELETE" });
      if (!res.ok) throw new Error("Unable to revoke peer");
      setNotice("Revoked in inventory. Apply the server configuration to enforce removal.");
      await refresh();
    } catch (err) { setError(String(err instanceof Error ? err.message : err)); }
    finally { setBusy(false); }
  }
  const active = peers.filter(p => p.revoked_at === null);
  return <main className="shell">
    <header className="mast">
      <div className="brand"><div className="mark" aria-hidden="true">◈</div><div><strong>GoreeCloud</strong><small>VPN · Private network</small></div></div>
      {signedIn && <button className="subtle" onClick={logout}>Sign out</button>}
    </header>
    {signedIn === null ? <p role="status">Loading management console…</p> : !signedIn ?
      <section className="login-card">
        <span className="eyebrow">PRIVATE ACCESS</span><h1>Welcome back.</h1>
        <p>Enter your local administrative access token. This console must be accessed through loopback or a trusted private HTTPS gateway.</p>
        <form onSubmit={signIn}>
          <label htmlFor="password">Admin access token</label>
          <input id="password" type="password" autoComplete="current-password"
            value={password} onChange={e => setPassword(e.target.value)} required minLength={32} />
          <button type="submit" disabled={busy}>{busy ? "Checking…" : "Open console"}</button>
        </form>
        {error && <p role="alert" className="error">{error}</p>}
      </section> :
      <>
        <div className="hero"><span className="eyebrow">NETWORK CONTROL</span>
          <h1>Private networking,<br/><em>under your control.</em></h1>
          <p>Manage trusted WireGuard peer identities without storing their private keys.</p>
        </div>
        <div className="stats">
          <article><span>Active peers</span><strong>{active.length}</strong><small>Enrolled in local inventory</small></article>
          <article><span>Revoked peers</span><strong>{peers.length - active.length}</strong><small>Pending applied configuration</small></article>
          <article><span>Data plane</span><strong className="status-text">Unverified</strong><small>Server rendering is offline only</small></article>
        </div>
        {error && <p className="error" role="alert">{error}</p>}
        {notice && <p className="notice" role="status">{notice}</p>}
        <div className="columns">
          <section className="panel"><div className="section-heading">
            <div><span className="eyebrow">INVENTORY</span><h2>Trusted devices</h2></div>
            <button className="subtle" onClick={() => void refresh()} disabled={busy}>Refresh</button>
          </div>
          {peers.length === 0 ? <div className="empty">No peers enrolled yet. Add a public key to begin.</div> :
            <ul className="peers">{peers.map(peer =>
              <li key={peer.id}>
                <div className="peer-icon" aria-hidden="true">⌁</div>
                <div className="peer-copy"><strong>{peer.name}</strong><code title={peer.public_key}>{terseKey(peer.public_key)}</code><small>{peer.address}</small></div>
                <div className="peer-action">{peer.revoked_at ? <span className="pill revoked">Revoked</span> :
                  <><span className="pill">Enrolled</span><button disabled={busy} className="danger" onClick={() => void revoke(peer)}>Revoke</button></>}</div>
              </li>
            )}</ul>}
          </section>
          <section className="panel"><span className="eyebrow">ENROLLMENT</span><h2>Add a peer</h2>
            <p>Generate the WireGuard private/public key pair locally on the target device. Paste only the public key here.</p>
            <form onSubmit={enroll}>
              <label htmlFor="deviceName">Device label</label><input id="deviceName" value={name} onChange={e => setName(e.target.value)} placeholder="Example: Family laptop" maxLength={64} required />
              <label htmlFor="publicKey">WireGuard public key</label><textarea id="publicKey" value={key} onChange={e => setKey(e.target.value)}
                placeholder="44-character base64 public key" rows={3} spellCheck={false} required />
              <button type="submit" disabled={busy}>{busy ? "Saving…" : "Enroll device"}</button>
            </form>
            <div className="footnote">Enrollment does not activate a tunnel. The operator must render and apply the updated WireGuard server configuration.</div>
          </section>
        </div>
      </>
    }
    <footer>GoreeCloud VPN · Development preview · <span>No telemetry or third-party analytics</span></footer>
  </main>;
}
