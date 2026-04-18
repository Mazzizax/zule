// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import { Resend } from "npm:resend@4";
import { handleCors, jsonResponse } from "../_shared/cors.ts";
import { checkEmailRateLimit, logEmailAttempt } from "../_shared/email-rate-limit.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  Deno.env.get("SUPABASE_SECRET_KEY")!;
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY")!;
const RESEND_FROM_EMAIL = Deno.env.get("RESEND_FROM_EMAIL")!;
const APP_AUTH_HOST = Deno.env.get("APP_AUTH_HOST") ?? "zule.mazzizax.net";

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const resend = new Resend(RESEND_API_KEY);

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  const options = handleCors(req);
  if (options) return options;
  if (req.method !== "POST") return jsonResponse({ error: "method_not_allowed" }, 405, origin);

  let body: { email?: string; password?: string };
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "invalid_json" }, 400, origin);
  }

  const email = (body.email ?? "").trim().toLowerCase();
  const password = body.password ?? "";

  if (!email || !password) {
    return jsonResponse({ error: "email_and_password_required" }, 400, origin);
  }
  if (password.length < 12) {
    return jsonResponse({ error: "password_too_short" }, 400, origin);
  }

  const ip = req.headers.get("x-forwarded-for") ?? null;

  const rateCheck = await checkEmailRateLimit(admin, email, ip);
  if (!rateCheck.allowed) {
    return jsonResponse(
      { error: "rate_limited", reason: rateCheck.reason, retry_after: rateCheck.retryAfterSec },
      429,
      origin,
    );
  }

  // Direct fetch to admin generate_link — the JS SDK nests `redirect_to`
  // inside `options`, which Supabase silently strips. Top-level `redirect_to`
  // is honored and preserves the full path pointing at our App Link.
  const linkRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/generate_link`, {
    method: "POST",
    headers: {
      "apikey": SUPABASE_SERVICE_ROLE_KEY,
      "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      type: "signup",
      email,
      password,
      redirect_to: `https://${APP_AUTH_HOST}/auth/callback`,
    }),
  });

  if (!linkRes.ok) {
    const detail = await linkRes.text();
    await logEmailAttempt(admin, email, "signup", ip, false);
    if (/already.*registered/i.test(detail) || /already exists/i.test(detail)) {
      return jsonResponse({ error: "email_already_registered" }, 409, origin);
    }
    return jsonResponse({ error: "generate_link_failed", detail }, linkRes.status, origin);
  }

  const linkJson = await linkRes.json() as any;
  const tokenHash: string | undefined = linkJson?.hashed_token;
  if (!tokenHash) return jsonResponse({ error: "no_token_hash" }, 500, origin);

  // Build confirmation URL pointing directly at the App-Linked domain.
  // Supabase's default action_link goes through SUPABASE_URL/auth/v1/verify
  // with a server-side 302; Android App Links only intercept the initial
  // user click, not server redirects, so that path opens in-browser.
  const actionLink = `https://${APP_AUTH_HOST}/auth/callback` +
    `?token_hash=${encodeURIComponent(tokenHash)}&type=signup`;

  const send = await resend.emails.send({
    from: RESEND_FROM_EMAIL,
    to: email,
    subject: "Confirm your Zule account",
    html: buildEmailHtml(actionLink),
    text: `Confirm your account: ${actionLink}`,
  });

  if ((send as any)?.error) {
    await logEmailAttempt(admin, email, "signup", ip, false);
    return jsonResponse(
      { error: "email_send_failed", detail: (send as any).error?.message },
      500,
      origin,
    );
  }

  await logEmailAttempt(admin, email, "signup", ip, true);
  return jsonResponse({ ok: true }, 200, origin);
});

function buildEmailHtml(url: string): string {
  return `<!doctype html>
<html>
  <body style="margin:0;padding:40px 20px;background:#080706;font-family:Georgia,'Cormorant Garamond',serif;color:#ece8e1;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;margin:0 auto;background:#111010;border:1px solid #1e1b18;border-radius:4px;padding:40px;">
      <tr><td style="text-align:center;padding-bottom:24px;">
        <h1 style="margin:0;font-size:22px;letter-spacing:6px;color:#C4A882;font-weight:700;">CONFIRM ACCOUNT</h1>
        <p style="margin:8px 0 0;color:#7d766d;font-size:12px;letter-spacing:2px;text-transform:uppercase;">one click to activate</p>
      </td></tr>
      <tr><td style="padding:8px 0 24px;color:#7d766d;font-size:16px;line-height:1.6;">
        Click the button below to verify your email and activate your Zule account. This link expires in 24 hours.
      </td></tr>
      <tr><td style="text-align:center;padding-bottom:20px;">
        <a href="${url}" style="display:inline-block;background:linear-gradient(135deg,#A08968 0%,#C4A882 40%,#D4BC9A 60%,#A08968 100%);color:#0a0908;padding:14px 32px;text-decoration:none;border-radius:4px;font-size:16px;letter-spacing:0.06em;font-weight:500;">Confirm Email</a>
      </td></tr>
      <tr><td style="padding-top:12px;color:#4a453e;font-size:12px;word-break:break-all;">
        Or paste this into your browser: <a href="${url}" style="color:#C4A882;">${url}</a>
      </td></tr>
    </table>
  </body>
</html>`;
}
