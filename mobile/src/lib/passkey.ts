import { Passkey } from 'react-native-passkey';
import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';
import { supabase } from './supabase';

const CREDENTIAL_ID_KEY = 'gatekeeper_passkey_credential_id';
const GATEKEEPER_URL = process.env.EXPO_PUBLIC_GATEKEEPER_URL;
const GATEKEEPER_KEY = process.env.EXPO_PUBLIC_GATEKEEPER_PUBLISHABLE_KEY || '';

/**
 * Convert standard base64 to base64url
 * react-native-passkey returns standard base64, WebAuthn expects base64url
 */
function base64ToBase64url(base64: string): string {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Register a new passkey for the authenticated user
 * Uses @simplewebauthn-compatible flow:
 * 1. GET registration options from server (includes server-generated challenge)
 * 2. Call device passkey API with those options
 * 3. POST the response in RegistrationResponseJSON format
 */
export async function registerPasskey(email: string): Promise<{ success: boolean; error?: string }> {
  try {
    const isSupported = await Passkey.isSupported();
    if (!isSupported) return { success: false, error: 'Passkeys not supported on this device' };

    // Get authenticated user and session
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return { success: false, error: 'Not authenticated' };

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return { success: false, error: 'No active session' };

    // 1. GET registration options from server
    console.log('[Passkey] Getting registration options from server...');
    const optionsUrl = `${GATEKEEPER_URL}/functions/v1/passkey-register?action=options`;
    const optionsResponse = await fetch(optionsUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'apikey': GATEKEEPER_KEY,
      },
    });

    if (!optionsResponse.ok) {
      const errorText = await optionsResponse.text();
      console.error('[Passkey] Failed to get options:', optionsResponse.status, errorText);
      throw new Error(`Failed to get registration options: ${errorText}`);
    }

    const { options, challenge_key } = await optionsResponse.json();
    console.log('[Passkey] Got registration options, challenge_key:', challenge_key);

    // 2. Call device passkey API with server-provided options
    console.log('[Passkey] Creating passkey with device...');
    const credential = await Passkey.create({
      challenge: options.challenge,
      rp: options.rp,
      user: options.user,
      pubKeyCredParams: options.pubKeyCredParams,
      authenticatorSelection: options.authenticatorSelection,
      timeout: options.timeout,
      excludeCredentials: options.excludeCredentials || [],
      attestation: options.attestation || 'none',
    });

    if (!credential) return { success: false, error: 'Passkey creation cancelled' };

    // Save credential_id locally for future authentication
    await SecureStore.setItemAsync(CREDENTIAL_ID_KEY, credential.id);
    console.log('[Passkey] Saved credential_id locally:', credential.id);

    // 3. POST the response in RegistrationResponseJSON format
    console.log('[Passkey] Sending registration response to server...');
    const registerUrl = `${GATEKEEPER_URL}/functions/v1/passkey-register`;
    const registerResponse = await fetch(registerUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${session.access_token}`,
        'apikey': GATEKEEPER_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        challenge_key: challenge_key,
        response: {
          id: credential.id,
          rawId: credential.id,
          type: 'public-key',
          response: {
            clientDataJSON: base64ToBase64url(credential.response.clientDataJSON),
            attestationObject: base64ToBase64url(credential.response.attestationObject),
            transports: ['internal'],
          },
          clientExtensionResults: {},
        },
        device_name: `${Platform.OS} - Device Key`,
      }),
    });

    if (!registerResponse.ok) {
      const errorText = await registerResponse.text();
      console.error('[Passkey] Registration failed:', registerResponse.status, errorText);
      throw new Error(`Registration failed: ${errorText}`);
    }

    console.log('[Passkey] Registration successful');
    return { success: true };
  } catch (error: any) {
    console.error('[Passkey] Registration error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Authenticate with a registered passkey
 * Uses @simplewebauthn-compatible flow:
 * 1. GET authentication challenge from server
 * 2. Call device passkey API to sign the challenge
 * 3. POST the response in AuthenticationResponseJSON format
 */
export async function authenticateWithPasskey(): Promise<{ success: boolean; error?: string }> {
  try {
    // Get stored credential_id
    const credentialId = await SecureStore.getItemAsync(CREDENTIAL_ID_KEY);
    if (!credentialId) {
      return { success: false, error: 'No passkey registered on this device' };
    }

    console.log('[Passkey] Using stored credential_id:', credentialId);

    // 1. GET authentication challenge from server
    const challengeUrl = `${GATEKEEPER_URL}/functions/v1/passkey-auth?credential_id=${encodeURIComponent(credentialId)}`;
    const challengeResponse = await fetch(challengeUrl, {
      method: 'GET',
      headers: {
        'apikey': GATEKEEPER_KEY,
      },
    });

    if (!challengeResponse.ok) {
      const errorText = await challengeResponse.text();
      throw new Error(`Challenge request failed: ${errorText}`);
    }

    const challengeData = await challengeResponse.json();
    console.log('[Passkey] Got challenge, challenge_key:', challengeData.challenge_key);

    // 2. Call device passkey API to sign the challenge
    console.log('[Passkey] Requesting assertion from device...');
    const assertion = await Passkey.get({
      challenge: challengeData.challenge,
      rpId: challengeData.rp_id || 'gatekeeper-nine.vercel.app',
      userVerification: 'preferred',
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
    });

    if (!assertion) return { success: false, error: 'Authentication cancelled' };
    console.log('[Passkey] Got assertion from device');

    // 3. POST the response in AuthenticationResponseJSON format
    const verifyUrl = `${GATEKEEPER_URL}/functions/v1/passkey-auth`;
    const verifyResponse = await fetch(verifyUrl, {
      method: 'POST',
      headers: {
        'apikey': GATEKEEPER_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        challenge_key: challengeData.challenge_key,
        response: {
          id: assertion.id,
          rawId: assertion.id,
          type: 'public-key',
          response: {
            clientDataJSON: base64ToBase64url(assertion.response.clientDataJSON),
            authenticatorData: base64ToBase64url(assertion.response.authenticatorData),
            signature: base64ToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle
              ? base64ToBase64url(assertion.response.userHandle)
              : undefined,
          },
          clientExtensionResults: {},
          authenticatorAttachment: 'platform',
        },
      }),
    });

    if (!verifyResponse.ok) {
      const errorText = await verifyResponse.text();
      throw new Error(`Verification failed: ${errorText}`);
    }

    const authData = await verifyResponse.json();
    console.log('[Passkey] Auth successful, user_id:', authData?.user_id);

    // Call mint-session to get Supabase tokens
    const mintUrl = `${GATEKEEPER_URL}/functions/v1/mint-session`;
    console.log('[Passkey] Calling mint-session...');

    const mintResponse = await fetch(mintUrl, {
      method: 'POST',
      headers: {
        'apikey': GATEKEEPER_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        verification_token: authData.verification_token,
        user_id: authData.user_id,
      }),
    });

    if (!mintResponse.ok) {
      const errorText = await mintResponse.text();
      throw new Error(`Session minting failed: ${errorText}`);
    }

    const sessionData = await mintResponse.json();
    console.log('[Passkey] Session minted, setting session...');

    // Set the session in Supabase client
    const { error: setSessionError } = await supabase.auth.setSession({
      access_token: sessionData.access_token,
      refresh_token: sessionData.refresh_token,
    });

    if (setSessionError) {
      throw new Error(`Failed to set session: ${setSessionError.message}`);
    }

    console.log('[Passkey] Session set successfully');
    return { success: true };
  } catch (error: any) {
    console.error('[Passkey] Auth error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if device has a registered passkey
 */
export async function hasStoredPasskey(): Promise<boolean> {
  const credentialId = await SecureStore.getItemAsync(CREDENTIAL_ID_KEY);
  return !!credentialId;
}

/**
 * Clear stored passkey (for logout or reset)
 */
export async function clearStoredPasskey(): Promise<void> {
  await SecureStore.deleteItemAsync(CREDENTIAL_ID_KEY);
}
