import { readFile } from "node:fs/promises";
import { join } from "node:path";

export type CommandRecord = {
  id: string;
  deviceId: string;
  hostname: string;
  type: string;
  payload: string;
  status: string;
  accepted: boolean;
  message: string;
  createdAt: string;
  updatedAt: string;
};

export async function loadCommands(deviceId?: string): Promise<CommandRecord[]> {
  try {
    const raw = await readFile(join(process.cwd(), "data", "commands.json"), "utf8");
    const parsed = JSON.parse(raw) as { commands?: CommandRecord[] };
    const list = parsed.commands ?? [];
    if (!deviceId) return list.slice().reverse();
    return list.filter((item) => item.deviceId === deviceId).reverse();
  } catch {
    return [];
  }
}

export const APID_ADMIN_URL = process.env.DEFENDSEC_APID_ADMIN ?? "http://127.0.0.1:47264";
