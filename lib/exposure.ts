import { APID_ADMIN_URL } from "@/lib/commands";
import { getAdminToken } from "@/lib/auth";
import {
  advisoryApiPath,
  exposureApiPath,
  trendApiPath,
  type ExposureAdvisoryResponse,
  type ExposureBucket,
  type ExposureListQuery,
  type ExposurePageResponse,
  type ExposureSummary,
  type ExposureTrend,
  type TrendQuery,
} from "@/lib/exposure-model";

/**
 * The exposure view as the control plane computes it (GET /v1/exposure/*). Each
 * function returns null if apid cannot be reached or is older than the exposure
 * API: callers say "unavailable", never show an empty list, since an empty list
 * reads as "all clear". The control plane ranks, pages and counts; nothing here
 * receives the whole fleet.
 */
async function get<T>(path: string): Promise<T | null> {
  try {
    const token = await getAdminToken();
    const response = await fetch(new URL(path, APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export function getExposureSummary(top = 5): Promise<ExposureSummary | null> {
  return get<ExposureSummary>(`/v1/exposure/summary?top=${top}`);
}

export function getExposurePage(q: Pick<ExposureListQuery, "bucket" | "status" | "cursor">): Promise<ExposurePageResponse | null> {
  return get<ExposurePageResponse>(exposureApiPath(q));
}

export function getExposureAdvisory(
  id: string,
  bucket: ExposureBucket,
  status: "open" | "resolved",
): Promise<ExposureAdvisoryResponse | null> {
  return get<ExposureAdvisoryResponse>(advisoryApiPath(id, bucket, status));
}

export function getExposureTrend(q: TrendQuery): Promise<ExposureTrend | null> {
  return get<ExposureTrend>(trendApiPath(q));
}
