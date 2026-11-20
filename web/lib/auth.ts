import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { NextRequest } from "next/server";

export const COOKIE_NAME = "gcvpn_session";
const SECONDS = 12 * 60 * 60;

function key(): string {
  const value = process.env.GCVPN_WEB_ADMIN_TOKEN || "";
  if (value.length < 32 || value.trim() !== value) {
    throw new Error("GCVPN_WEB_ADMIN_TOKEN must be at least 32 characters");
  }
  return value;
}
function mac(expires: string): string {
  return createHmac("sha256", key()).update("gcvpn:session:v1:" + expires).digest("hex");
}
export function fixedTimeEqual(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
export function correctPassword(value: unknown): boolean {
  return typeof value === "string" && fixedTimeEqual(value, key());
}
export function issueSession(): string {
  const exp = String(Math.floor(Date.now() / 1000) + SECONDS);
  return exp + "." + mac(exp);
}
export function verifySession(value: string | undefined): boolean {
  if (!value || !/^\d{10}\.[0-9a-f]{64}$/.test(value)) return false;
  const [exp, sig] = value.split(".");
  const secondsLeft = Number(exp) - Math.floor(Date.now() / 1000);
  return secondsLeft > 0 && secondsLeft <= SECONDS && fixedTimeEqual(sig, mac(exp));
}
export async function authorized(): Promise<boolean> {
  const c = await cookies();
  return verifySession(c.get(COOKIE_NAME)?.value);
}
export function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && origin === new URL(request.url).origin;
}
export function secureCookie(request: NextRequest): boolean {
  return new URL(request.url).protocol === "https:";
}
