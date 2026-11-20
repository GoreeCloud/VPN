import { NextRequest, NextResponse } from "next/server";
import { authorized, sameOrigin } from "@/lib/auth";
import { backend } from "@/lib/backend";

export const runtime = "nodejs";
export async function DELETE(
  request: NextRequest, { params }: { params: Promise<{ id: string }> }
) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  if (!await authorized()) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { id } = await params;
  if (!/^[0-9a-f]{32}$/.test(id)) return NextResponse.json({ error: "Invalid peer ID" }, { status: 400 });
  try {
    const upstream = await backend("/api/v1/peers/" + id, { method: "DELETE" });
    return NextResponse.json(await upstream.json(), { status: upstream.status });
  } catch {
    return NextResponse.json({ error: "Management service unavailable" }, { status: 503 });
  }
}
