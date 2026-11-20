import { NextRequest, NextResponse } from "next/server";
import { COOKIE_NAME, correctPassword, issueSession, sameOrigin, secureCookie } from "@/lib/auth";

export const runtime = "nodejs";
export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  try {
    const raw = await request.text();
    if (raw.length > 4096) return NextResponse.json({ error: "Invalid request" }, { status: 413 });
    const json = JSON.parse(raw);
    if (!correctPassword(json?.password)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const response = new NextResponse(null, { status: 204 });
    response.cookies.set(COOKIE_NAME, issueSession(), {
      httpOnly: true, sameSite: "strict", secure: secureCookie(request),
      path: "/", maxAge: 12 * 60 * 60
    });
    return response;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}
export async function DELETE(request: NextRequest) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const response = new NextResponse(null, { status: 204 });
  response.cookies.set(COOKIE_NAME, "", {
    httpOnly: true, sameSite: "strict", secure: secureCookie(request),
    path: "/", maxAge: 0
  });
  return response;
}
