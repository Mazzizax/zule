// deno-lint-ignore-file no-explicit-any

/**
 * Per-email + per-IP rate limiting for signup/resend/reset flows. Prevents
 * a hostile actor from spamming Resend emails to a victim's inbox and
 * burning sender reputation. Also bounds enumeration attacks that probe
 * which emails are registered.
 *
 * Policy:
 *   - Per email: max 3 attempts in 15 minutes.
 *   - Per IP:    max 10 attempts in 15 minutes (any email).
 */

export type RateLimitDecision =
  | { allowed: true }
  | { allowed: false; reason: "email_throttled" | "ip_throttled"; retryAfterSec: number };

const EMAIL_LIMIT = 3;
const IP_LIMIT = 10;
const WINDOW_MS = 15 * 60 * 1000;

export async function checkEmailRateLimit(
  admin: any,
  email: string,
  ip: string | null,
): Promise<RateLimitDecision> {
  const since = new Date(Date.now() - WINDOW_MS).toISOString();

  const { count: emailCount } = await admin
    .from("auth_email_attempts")
    .select("id", { count: "exact", head: true })
    .eq("email", email.toLowerCase())
    .gte("attempted_at", since);

  if ((emailCount ?? 0) >= EMAIL_LIMIT) {
    return { allowed: false, reason: "email_throttled", retryAfterSec: 900 };
  }

  if (ip) {
    const { count: ipCount } = await admin
      .from("auth_email_attempts")
      .select("id", { count: "exact", head: true })
      .eq("ip", ip)
      .gte("attempted_at", since);
    if ((ipCount ?? 0) >= IP_LIMIT) {
      return { allowed: false, reason: "ip_throttled", retryAfterSec: 900 };
    }
  }

  return { allowed: true };
}

export async function logEmailAttempt(
  admin: any,
  email: string,
  kind: "signup" | "resend" | "reset",
  ip: string | null,
  succeeded: boolean,
): Promise<void> {
  await admin.from("auth_email_attempts").insert({
    email: email.toLowerCase(),
    kind,
    ip,
    succeeded,
  });
}
