import { join } from "node:path";

export function dataDir(): string {
  return process.env.DEFENDSEC_DATA_DIR?.trim() || join(process.cwd(), "data");
}

export function dataPath(...parts: string[]): string {
  return join(/* turbopackIgnore: true */ dataDir(), ...parts);
}
