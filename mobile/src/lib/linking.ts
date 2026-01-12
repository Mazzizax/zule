import * as Linking from 'expo-linking';

/**
 * Deep Linking Configuration for Gatekeeper Mobile
 *
 * Handles Android App Links (verified HTTPS links) and
 * custom scheme deep links as fallback.
 */

// Valid callback URL prefixes that we'll redirect to
const VALID_CALLBACK_PREFIXES = [
  'dawgtag://',        // Dawg Tag custom scheme
  'exp://',            // Expo development
  'https://',          // HTTPS callbacks
];

/**
 * Validate a callback URL
 *
 * @param callbackUrl - The callback URL to validate
 * @returns true if the callback URL is valid
 */
export function isValidCallbackUrl(callbackUrl: string | null): boolean {
  if (!callbackUrl) return false;

  return VALID_CALLBACK_PREFIXES.some(prefix =>
    callbackUrl.startsWith(prefix)
  );
}

/**
 * Parse incoming deep link URL to extract callback parameter
 *
 * Expected format: https://gatekeeper-nine.vercel.app/auth?callback=dawgtag://...
 *
 * @param url - The incoming deep link URL
 * @returns The callback URL or null
 */
export function parseAuthDeepLink(url: string): string | null {
  try {
    const parsed = Linking.parse(url);
    return parsed.queryParams?.callback as string | null;
  } catch {
    return null;
  }
}

/**
 * Open a URL (for redirecting back to Dawg Tag)
 *
 * @param url - The URL to open
 */
export async function openUrl(url: string): Promise<void> {
  const canOpen = await Linking.canOpenURL(url);

  if (canOpen) {
    await Linking.openURL(url);
  } else {
    throw new Error(`Cannot open URL: ${url}`);
  }
}

/**
 * Get the app's linking configuration for expo-router
 */
export const linkingConfig = {
  prefixes: [
    'gatekeeper://',                           // Custom scheme (fallback)
    'https://gatekeeper-nine.vercel.app',      // Android App Links / Universal Links
  ],
};
