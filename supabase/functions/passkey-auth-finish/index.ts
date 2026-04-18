// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyAuthenticationResponse } from "npm:@simplewebauthn/server@13";
import { handleCors, jsonResponse } from "../_shared/cors.ts";
import { EXPECTED_ORIGINS, RP_ID } from "../_shared/webauthn-config.ts";
import { b64UrlToBytes } from "../_shared/b64url.ts";

/**
 * Verifies a passkey assertion and mints a real Supabase session. This is
 * zule's own passkey sign-in path (not the Vinzrik attestation flow served
 * by the legacy passkey-auth function).
 *
 * Server-issued challenge is looked up from passkey_challenges; assertion
 * is verified against the stored public key; counter rollback is treated
 * as clone detection; per-credential rate limit caps brute-force attempts.
 * A native Supabase session is generated via admin.generateLink(magiclink)
 * + anon.verifyOtp, so the client can importSession directly.
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  Deno.env.get("SUPABASE_SECRET_KEY")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

if (!SUPABASE_ANON_KEY) {
  console.error(
    "passkey-auth-finish: SUPABASE_ANON_KEY missing from env — verifyOtp will fail",
  );
}

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");
  const pre = handleCors(req);
  if (pre) return pre;
  if (req.method !== "POST") return jsonResponse({ error: "method_not_allowed" }, 405, origin);

  let body: { handle?: string; response?: any };
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "invalid_json" }, 400, origin);
  }
  if (!body.handle || !body.response?.id) {
    return jsonResponse({ error: "missing_fields" }, 400, origin);
  }

  const { data: chal, error: chalErr } = await admin
    .from("passkey_challenges")
    .select("challenge, expires_at, challenge_key")
    .eq("challenge_key", body.handle)
    .single();

  if (chalErr || !chal) return jsonResponse({ error: "unknown_challenge" }, 400, origin);
  if (!chal.challenge_key?.startsWith("auth-strict:")) {
    return jsonResponse({ error: "wrong_challenge_kind" }, 400, origin);
  }
  if (new Date(chal.expires_at).getTime() < Date.now()) {
    return jsonResponse({ error: "challenge_expired" }, 400, origin);
  }

  const { data: cred, error: credErr } = await admin
    .from("user_passkeys")
    .select("id, user_id, credential_id, public_key, counter, transports")
    .eq("credential_id", body.response.id)
    .eq("is_active", true)
    .single();

  if (credErr || !cred) return jsonResponse({ error: "unknown_credential" }, 400, origin);

  const ip = req.headers.get("x-forwarded-for") ?? null;

  // Per-credential rate limit: 5 failed attempts in the last 5 min → lock
  // this credential out for 5 more minutes. Independent of any IP-based
  // limiting elsewhere.
  const windowStart = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const { count: recentFailures } = await admin
    .from("passkey_auth_attempts")
    .select("id", { count: "exact", head: true })
    .eq("credential_id", cred.credential_id)
    .eq("succeeded", false)
    .gte("attempted_at", windowStart);
  if ((recentFailures ?? 0) >= 5) {
    await admin.from("passkey_auth_attempts").insert({
      credential_id: cred.credential_id,
      user_id: cred.user_id,
      succeeded: false,
      reason: "rate_limited",
      ip,
    });
    console.warn(
      `rate_limited credential_id=${cred.credential_id} user_id=${cred.user_id} failures=${recentFailures}`,
    );
    return jsonResponse({ verified: false, error: "rate_limited" }, 429, origin);
  }

  let verification: any;
  try {
    verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: chal.challenge,
      expectedOrigin: EXPECTED_ORIGINS,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credential_id,
        publicKey: b64UrlToBytes(cred.public_key),
        counter: Number(cred.counter),
        transports: cred.transports ?? undefined,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    const msg = (e as Error).message;

    // @simplewebauthn rejects when newCounter <= stored counter with a
    // message containing "counter" — that's a potential cloned authenticator.
    // Log loudly for review and return a clone-specific hint.
    if (/counter/i.test(msg)) {
      console.error(
        `POTENTIAL_CLONE credential_id=${cred.credential_id} user_id=${cred.user_id} stored_counter=${cred.counter} msg=${msg}`,
      );
      await admin.from("passkey_auth_attempts").insert({
        credential_id: cred.credential_id,
        user_id: cred.user_id,
        succeeded: false,
        reason: "counter_rollback",
        ip,
      });
      return jsonResponse(
        { verified: false, error: "counter_rollback", hint: "clone_suspected" },
        401,
        origin,
      );
    }

    console.error(
      "verifyAuthenticationResponse threw",
      msg,
      JSON.stringify(body.response),
    );
    await admin.from("passkey_auth_attempts").insert({
      credential_id: cred.credential_id,
      user_id: cred.user_id,
      succeeded: false,
      reason: "verify_threw",
      ip,
    });
    return jsonResponse(
      {
        verified: false,
        error: "verification_failed",
        hint: "provider_response_malformed",
        detail: msg,
      },
      400,
      origin,
    );
  }

  if (!verification.verified) {
    console.error(
      "verifyAuthenticationResponse returned !verified",
      JSON.stringify(body.response),
    );
    await admin.from("passkey_auth_attempts").insert({
      credential_id: cred.credential_id,
      user_id: cred.user_id,
      succeeded: false,
      reason: "not_verified",
      ip,
    });
    return jsonResponse({ verified: false, error: "assertion_invalid" }, 401, origin);
  }

  await admin.from("passkey_auth_attempts").insert({
    credential_id: cred.credential_id,
    user_id: cred.user_id,
    succeeded: true,
    reason: null,
    ip,
  });

  await admin
    .from("user_passkeys")
    .update({
      counter: verification.authenticationInfo?.newCounter ?? cred.counter,
      last_used_at: new Date().toISOString(),
    })
    .eq("id", cred.id);

  await admin.from("passkey_challenges").delete().eq("challenge_key", body.handle);

  // Mint a native Supabase session so the client can importSession. This is
  // the missing piece in zule's existing passkey-auth path.
  const userRes = await admin.auth.admin.getUserById(cred.user_id);
  if (userRes.error || !userRes.data?.user?.email) {
    return jsonResponse({ verified: false, error: "user_lookup_failed" }, 500, origin);
  }
  const email = userRes.data.user.email;

  const link = await admin.auth.admin.generateLink({
    type: "magiclink",
    email,
  });
  if (link.error || !link.data?.properties?.email_otp) {
    return jsonResponse({ verified: false, error: "generate_link_failed" }, 500, origin);
  }

  const otp = link.data.properties.email_otp;
  const anon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  const verified = await anon.auth.verifyOtp({ email, token: otp, type: "email" });
  if (verified.error || !verified.data?.session) {
    console.error(
      "verifyOtp failed",
      verified.error?.message,
      JSON.stringify(verified.data),
    );
    return jsonResponse(
      { verified: false, error: "otp_exchange_failed", detail: verified.error?.message },
      500,
      origin,
    );
  }

  const s = verified.data.session;
  return jsonResponse(
    {
      verified: true,
      access_token: s.access_token,
      refresh_token: s.refresh_token,
      expires_in: s.expires_in,
      token_type: s.token_type,
      user: verified.data.user,
    },
    200,
    origin,
  );
});
