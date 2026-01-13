import { Passkey } from 'react-native-passkey';
import * as Crypto from 'expo-crypto';
import { Platform } from 'react-native';
import { supabase } from './supabase';

/**
 * Gatekeeper Production-Grade Passkey Manager
 */

// Robust Base64URL implementation for React Native (No btoa/TextEncoder needed)
const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function toBase64URL(bytes: Uint8Array): string {
  let base64 = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    base64 += chars[bytes[i] >> 2];
    base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    base64 += chars[bytes[i + 2] & 63];
  }
  
  // Clean up padding and convert to URL-safe
  return base64
    .substring(0, Math.ceil((len * 8) / 6))
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function stringToUint8Array(str: string): Uint8Array {
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return arr;
}

export async function registerPasskey(email: string): Promise<{ success: boolean; error?: string }> {
  try {
    const isSupported = await Passkey.isSupported();
    if (!isSupported) return { success: false, error: 'Passkeys not supported' };

    const challenge = toBase64URL(Crypto.getRandomBytes(32));
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return { success: false, error: 'Not authenticated' };

    const rpId = 'gatekeeper-nine.vercel.app'; 

    const request = {
      challenge,
      rp: { name: 'Gatekeeper', id: rpId },
      user: {
        id: toBase64URL(stringToUint8Array(user.id)),
        name: email,
        displayName: email,
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
    };

    const credential = await Passkey.create(request);
    if (!credential) return { success: false, error: 'Cancelled' };

    const { data: { session } } = await supabase.auth.getSession();
    const { error: serverError } = await supabase.functions.invoke('passkey-register', {
      body: {
        credential_id: credential.id,
        public_key: credential.rawId,
        device_name: `${Platform.OS} - Device Key`,
        authenticator_type: 'platform',
      },
      headers: { Authorization: `Bearer ${session?.access_token}` }
    });

    if (serverError) throw serverError;
    return { success: true };
  } catch (error: any) {
    console.error('[Passkey] Registration error:', error);
    return { success: false, error: error.message };
  }
}

export async function authenticateWithPasskey(): Promise<{ success: boolean; error?: string }> {
  try {
    const { data: challengeData, error: challengeError } = await supabase.functions.invoke('passkey-auth', {
      method: 'GET'
    });
    if (challengeError) throw challengeError;

    const assertion = await Passkey.get({
      challenge: challengeData.challenge,
      rpId: 'gatekeeper-nine.vercel.app',
      userVerification: 'required',
    });

    if (!assertion) return { success: false, error: 'Cancelled' };

    const { error: verifyError } = await supabase.functions.invoke('passkey-auth', {
      body: {
        challenge_key: challengeData.challenge_key,
        credential_id: assertion.id,
        authenticator_data: assertion.response.authenticatorData,
        client_data_json: assertion.response.clientDataJSON,
        signature: assertion.response.signature,
      }
    });

    if (verifyError) throw verifyError;
    return { success: true };
  } catch (error: any) {
    console.error('[Passkey] Auth error:', error);
    return { success: false, error: error.message };
  }
}
