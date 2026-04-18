// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyRegistrationResponse } from "npm:@simplewebauthn/server@13";
import { handleCors, jsonResponse } from "../_shared/cors.ts";
import { EXPECTED_ORIGINS, RP_ID } from "../_shared/webauthn-config.ts";
import { bytesToB64Url } from "../_shared/b64url.ts";

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

  let body: { handle?: string; response?: any };
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "invalid_json" }, 400, origin);
  }
  if (!body.handle || !body.response) {
    return jsonResponse({ error: "missing_fields" }, 400, origin);
  }

  const { data: chal, error: chalErr } = await admin
    .from("passkey_challenges")
    .select("challenge, user_id, expires_at, challenge_key")
    .eq("challenge_key", body.handle)
    .single();

  if (chalErr || !chal) return jsonResponse({ error: "unknown_challenge" }, 400, origin);
  if (!chal.challenge_key?.startsWith("reg-strict:")) {
    return jsonResponse({ error: "wrong_challenge_kind" }, 400, origin);
  }
  if (chal.user_id !== user.id) return jsonResponse({ error: "user_mismatch" }, 403, origin);
  if (new Date(chal.expires_at).getTime() < Date.now()) {
    return jsonResponse({ error: "challenge_expired" }, 400, origin);
  }

  let verification: any;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: chal.challenge,
      expectedOrigin: EXPECTED_ORIGINS,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (e) {
    console.error(
      "verifyRegistrationResponse threw",
      (e as Error).message,
      JSON.stringify(body.response),
    );
    return jsonResponse(
      {
        verified: false,
        error: "verification_failed",
        hint: "provider_response_malformed",
        detail: (e as Error).message,
      },
      400,
      origin,
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    console.error(
      "verifyRegistrationResponse returned !verified",
      JSON.stringify(body.response),
    );
    return jsonResponse(
      { verified: false, error: "verification_failed", hint: "provider_response_malformed" },
      400,
      origin,
    );
  }

  const { credential, credentialDeviceType } = verification.registrationInfo;

  // Public key stored base64url-encoded into a text column. PostgREST returns
  // bytea as `\x...` hex escapes that @simplewebauthn cannot decode directly.
  const publicKeyB64 = bytesToB64Url(credential.publicKey as Uint8Array);

  const insert = await admin.from("user_passkeys").insert({
    user_id: user.id,
    credential_id: credential.id,
    public_key: publicKeyB64,
    counter: credential.counter,
    transports: body.response?.response?.transports ?? null,
    authenticator_type: credentialDeviceType === "multiDevice" ? "platform" : credentialDeviceType,
    is_active: true,
  });

  if (insert.error) {
    return jsonResponse(
      { verified: false, error: "store_failed", detail: insert.error.message },
      500,
      origin,
    );
  }

  await admin.from("passkey_challenges").delete().eq("challenge_key", body.handle);

  return jsonResponse({ verified: true, credentialId: credential.id }, 200, origin);
});
