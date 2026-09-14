// Minimal in-memory login throttle. The whole auth model is one bearer
// token with no username and no account lockout, so without this, guessing
// it is just an unlimited-speed HTTP loop. This is deliberately simple for
// a single-process, self-hosted deployment — not a distributed rate
// limiter — and resets on restart.
//
// Client attribution is best-effort: behind a trusted reverse proxy,
// X-Forwarded-For identifies the real caller and this throttles them
// individually. Exposed directly (no proxy), the header is
// attacker-controlled, so a determined attacker can spoof a fresh key per
// request to dodge per-key throttling — but the bucket cap below still
// bounds total memory use, and a same-key flood (the common case) is still
// caught.

type Bucket = { count: number; windowStart: number };

const WINDOW_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const MAX_TRACKED_KEYS = 5000;

const buckets = new Map<string, Bucket>();

function currentBucket(key: string, now: number): Bucket | undefined {
  const existing = buckets.get(key);
  if (!existing) return undefined;
  if (now - existing.windowStart >= WINDOW_MS) {
    buckets.delete(key);
    return undefined;
  }
  return existing;
}

export function isRateLimited(
  key: string,
  now = Date.now(),
): { limited: boolean; retryAfterSeconds: number } {
  const bucket = currentBucket(key, now);
  if (!bucket || bucket.count < MAX_ATTEMPTS) {
    return { limited: false, retryAfterSeconds: 0 };
  }
  const retryAfterSeconds = Math.max(1, Math.ceil((bucket.windowStart + WINDOW_MS - now) / 1000));
  return { limited: true, retryAfterSeconds };
}

export function recordFailedAttempt(key: string, now = Date.now()): void {
  const bucket = currentBucket(key, now);
  if (bucket) {
    bucket.count += 1;
    return;
  }
  if (buckets.size >= MAX_TRACKED_KEYS) {
    const oldestKey = buckets.keys().next().value;
    if (oldestKey !== undefined) buckets.delete(oldestKey);
  }
  buckets.set(key, { count: 1, windowStart: now });
}

export function clearAttempts(key: string): void {
  buckets.delete(key);
}

export function loginRateLimitKey(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  const first = forwardedFor?.split(",")[0]?.trim();
  return first || "unattributed";
}
