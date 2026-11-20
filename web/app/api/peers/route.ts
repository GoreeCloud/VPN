import { NextRequest, NextResponse } from "next/server";
import { authorized, sameOrigin } from "@/lib/auth";
import { backend } from "@/lib/backend";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!await authorized()) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const upstream = await backend("/api/v1/peers");
    if (!upstream.ok) throw new Error("Backend request failed");
    return NextResponse.json(await upstream.json(), {
      headers: { "Cache-Control": "no-store" }
    });
  } catch {
    return NextResponse.json({ error: "Management service unavailable" }, { status: 503 });
  }
}

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  if (!await authorized()) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const raw = await request.text();
    if (raw.length > 4096) return NextResponse.json({ error: "Request too large" }, { status: 413 });
    const data: unknown = JSON.parse(raw);
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      return NextResponse.json({ error: "Invalid peer" }, { status: 400 });
    }
    const body = data as Record<string, unknown>;
    if (Object.keys(body).sort().join(",") !== "name,public_key" ||
        typeof body.name !== "string" || typeof body.public_key !== "string") {
      return NextResponse.json({ error: "Expected name and public key" }, { status: 400 });
    }
    const upstream = await backend("/api/v1/peers", {
      method: "POST",
      body: JSON.stringify({ name: body.name, public_key: body.public_key })
    });
    return NextResponse.json(await upstream.json(), { status: upstream.status });
  } catch {
    return NextResponse.json({ error: "Unable to enroll peer" }, { status: 503 });
  }
}
