// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import { generateRegistrationOptions } from "npm:@simplewebauthn/server@13";
import { handleCors, jsonResponse } from "../_shared/cors.ts";
import { RP_ID, RP_NAME } from "../_shared/webauthn-config.ts";

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

  const authHeader = req.headers.get("Authorization") ?? "";
  const accessToken = authHeader.replace(/^Bearer /i, "");
  if (!accessToken) return jsonResponse({ error: "unauthorized" }, 401, origin);

  const userRes = await admin.auth.getUser(accessToken);
  if (userRes.error || !userRes.data?.user) {
    return jsonResponse({ error: "unauthorized" }, 401, origin);
  }
  const user = userRes.data.user;

  const { data: existing } = await admin
    .from("user_passkeys")
    .select("credential_id, transports")
    .eq("user_id", user.id)
    .eq("is_active", true);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.email ?? user.id,
    userID: new TextEncoder().encode(user.id),
    attestationType: "none",
    excludeCredentials:
      existing?.map((c: any) => ({
        id: c.credential_id,
        transports: c.transports ?? undefined,
      })) ?? [],
    // Stricter than the legacy passkey-register function. "platform" + resident
    // required forces Google Password Manager / platform authenticator with a
    // discoverable credential; userVerification=required demands biometric.
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
      authenticatorAttachment: "platform",
    },
  });

  // Server stores the challenge. Client receives the challenge only to pass
  // through the authenticator — it must never originate one.
  const challengeKey = `reg-strict:${user.id}:${Date.now()}`;
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const insert = await admin.from("passkey_challenges").insert({
    challenge_key: challengeKey,
    user_id: user.id,
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
