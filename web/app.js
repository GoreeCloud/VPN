"use strict";
// Tokens are not stored in localStorage/sessionStorage, URL, or browser logs.
const tokenInput = document.querySelector("#token");
const authForm = document.querySelector("#auth-form");
const disconnect = document.querySelector("#disconnect");
const refresh = document.querySelector("#refresh");
const createForm = document.querySelector("#create-form");
const createButton = document.querySelector("#register");
const status = document.querySelector("#status");
const peers = document.querySelector("#peers");
let token = "";

function message(text) { status.textContent = text; }
function connected(value) {
  refresh.disabled = !value;
  createButton.disabled = !value;
  disconnect.hidden = !value;
  tokenInput.disabled = value;
}
async function api(path, options = {}) {
  if (!token) throw new Error("Not connected");
  const response = await fetch(path, {
    ...options,
    headers: {
      "Authorization": "Bearer " + token,
      "Accept": "application/json",
      ...(options.body ? {"Content-Type": "application/json"} : {})
    },
    redirect: "error",
    cache: "no-store",
    credentials: "omit",
  });
  if (!response.ok) throw new Error("API returned HTTP " + response.status);
  return response.json();
}
function peerItem(peer) {
  const li = document.createElement("li");
  const title = document.createElement("strong");
  title.textContent = peer.name || "Unnamed peer";
  const meta = document.createElement("p");
  meta.textContent = (peer.address || "Address pending") + " · " +
    (peer.revoked_at ? "Revoked" : "Registered (no tunnel verified)");
  li.append(title, meta);
  if (!peer.revoked_at) {
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.textContent = "Revoke identity";
    revoke.setAttribute("aria-label", "Revoke " + peer.name);
    revoke.addEventListener("click", async () => {
      if (!window.confirm("Revoke this peer's registered identity? This action cannot be undone.")) return;
      try {
        await api("/v1/peers/" + encodeURIComponent(peer.id) + "/revoke", {method:"POST"});
        await listPeers();
      } catch { message("Unable to revoke identity. Check API permissions."); }
    });
    li.append(revoke);
  }
  return li;
}
async function listPeers() {
  const data = await api("/v1/peers");
  peers.replaceChildren();
  const items = Array.isArray(data.peers) ? data.peers : [];
  if (items.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No registered peer identities";
    peers.append(item);
  }
  for (const peer of items) peers.append(peerItem(peer));
  message("Connected · " + items.length + " registered peer identities (not tunnel sessions)");
}
authForm.addEventListener("submit", async e => {
  e.preventDefault();
  const candidate = tokenInput.value;
  tokenInput.value = "";
  if (candidate.length < 32) { message("Token is too short"); return; }
  token = candidate;
  try {
    const info = await api("/v1/info");
    if (info.tunnel_operational !== false) throw new Error("Unexpected API contract");
    connected(true);
    await listPeers();
  } catch {
    token = "";
    connected(false);
    message("Authentication or API connection failed");
  }
});
disconnect.addEventListener("click", () => {
  token = "";
  peers.replaceChildren();
  connected(false);
  message("Disconnected; token cleared from memory");
});
refresh.addEventListener("click", () => { listPeers().catch(() => message("Unable to refresh peers")); });
createForm.addEventListener("submit", async e => {
  e.preventDefault();
  const name = document.querySelector("#peer-name").value.trim();
  const public_key = document.querySelector("#pubkey").value.trim();
  if (!window.confirm("Register this device's PUBLIC key? This will not activate a tunnel.")) return;
  try {
    await api("/v1/peers", {method:"POST",body:JSON.stringify({name,public_key})});
    createForm.reset();
    await listPeers();
  } catch { message("Peer registration failed; check name/key or duplicate identity"); }
});
