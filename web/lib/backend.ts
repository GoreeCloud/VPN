export async function backend(path: string, init: RequestInit = {}): Promise<Response> {
  const admin = process.env.GCVPN_ADMIN_TOKEN || "";
  if (admin.length < 32) throw new Error("GCVPN_ADMIN_TOKEN is not configured");
  const input = process.env.GCVPN_BACKEND_URL || "http://127.0.0.1:8787";
  const url = new URL(input);
  if (url.protocol !== "http:" || !["localhost", "127.0.0.1"].includes(url.hostname) ||
      url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("GCVPN_BACKEND_URL must be an uncredentialed loopback HTTP origin");
  }
  return fetch(new URL(path, url), {
    ...init,
    cache: "no-store",
    headers: {
      "Authorization": "Bearer " + admin,
      ...(init.body ? { "Content-Type": "application/json" } : {})
    }
  });
}
