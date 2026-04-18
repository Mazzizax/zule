// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import { generateAuthenticationOptions } from "npm:@simplewebauthn/server@13";
import { handleCors, jsonResponse } from "../_shared/cors.ts";
import { RP_ID } from "../_shared/webauthn-config.ts";

/**
 * Server-issued challenge for passkey sign-in that mints a real Supabase
 * session. Paired with passkey-auth-finish below. Distinct from zule's
 * legacy passkey-auth (which returns an ES256 attestation for the Vinzrik
 * hand-off) — that still has callers and remains untouched.
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  Deno.env.get("SUPABASE_SECRET_KEY")!;

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  const pre = handleCors(req);
  if (pre) return pre;
  if (req.method !== "POST") return jsonResponse({ error: "method_not_allowed" }, 405, origin);

  // Empty body permitted — usernameless flow. `email` is accepted for
  // forwards-compatibility but ignored for Phase 1 to avoid enumeration.
  try {
    await req.json();
  } catch {
    // ignore
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "required",
    allowCredentials: [],
  });

  const challengeKey = `auth-strict:${crypto.randomUUID()}:${Date.now()}`;
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const insert = await admin.from("passkey_challenges").insert({
    challenge_key: challengeKey,
    user_id: null,
    challenge: options.challenge,
    expires_at: expiresAt,
  });

  if (insert.error) {
    return jsonResponse(
      { error: "challenge_store_failed", detail: insert.error.message },
      500,
      origin,
    );
  }

  return jsonResponse({ handle: challengeKey, options }, 200, origin);
});
