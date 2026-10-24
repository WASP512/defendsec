import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadMtlsDevices, loadMtlsFimEvents, mergeDevices } from "@/lib/mtls-agents";
import { apidId, evaluateDevice, type VulnInput } from "@/lib/policies";
import { getFindingsSummary } from "@/lib/findings";
import { storeErrorResponse, unauthorizedIfNotAuthenticated } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAuthenticated(request);
  if (denied) return denied;
  try {
    const { id } = await params;
    const store = await ensureStore();
    const device = mergeDevices(store.devices, await loadMtlsDevices()).find(
      (d) => d.id === id || d.mtlsDeviceId === id,
    );
    if (!device) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }
    const summaries = await getFindingsSummary(apidId(device));
    const vulns: VulnInput = summaries
      ? { available: true, summary: summaries.get(apidId(device)) }
      : { available: false };
    return NextResponse.json({
      device: publicDevice(device),
      policies: evaluateDevice(device, [...(await loadMtlsFimEvents()), ...store.fimEvents], store.triages, vulns),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}
