/**
 * Security utilities for Zule Edge Functions
 *
 * Provides:
 * - Timing-safe string comparison
 * - Input validation
 * - CORS origin validation
 */

/**
 * Timing-safe string comparison to prevent timing attacks.
 * Both strings are compared in constant time regardless of where they differ.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  // If lengths differ, we still need to do constant-time comparison
  // to avoid leaking length information
  if (aBytes.length !== bBytes.length) {
    // Compare against self to maintain constant time
    const dummy = new Uint8Array(aBytes.length);
    await crypto.subtle.timingSafeEqual(aBytes, dummy).catch(() => false);
    return false;
  }

  // Use Web Crypto API for timing-safe comparison
  // Since crypto.subtle.timingSafeEqual doesn't exist in all runtimes,
  // we implement our own constant-time comparison
  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }
  return result === 0;
}

/**
 * Timing-safe HMAC comparison for webhook signatures
 */
export async function timingSafeHmacEqual(
  expected: string,
  actual: string
): Promise<boolean> {
  // Normalize both to lowercase hex
  const expectedNorm = expected.toLowerCase();
  const actualNorm = actual.toLowerCase();

  return timingSafeEqual(expectedNorm, actualNorm);
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate IANA timezone
 */
export function isValidTimezone(tz: string): boolean {
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate display name (safe characters, reasonable length)
 */
export function isValidDisplayName(name: string): { valid: boolean; error?: string } {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: 'Display name is required' };
  }

  if (name.length < 1 || name.length > 100) {
    return { valid: false, error: 'Display name must be 1-100 characters' };
  }

  // Allow letters, numbers, spaces, hyphens, underscores, periods
  // Disallow control characters and most special characters
  const safeNameRegex = /^[\p{L}\p{N}\s._-]+$/u;
  if (!safeNameRegex.test(name)) {
    return { valid: false, error: 'Display name contains invalid characters' };
  }

  // No leading/trailing whitespace
  if (name !== name.trim()) {
    return { valid: false, error: 'Display name cannot have leading/trailing spaces' };
  }

  return { valid: true };
}

/**
 * Validate locale format (BCP 47)
 */
export function isValidLocale(locale: string): boolean {
  try {
    // Use Intl to validate locale
    const canonical = Intl.getCanonicalLocales(locale);
    return canonical.length > 0;
  } catch {
    return false;
  }
}

/**
 * CORS origin validation
 */
export interface CorsConfig {
  allowedOrigins: string[];
  allowCredentials?: boolean;
}

export function validateOrigin(origin: string | null, config: CorsConfig): boolean {
  if (!origin) return false;

  // Normalize origin (remove trailing slash)
  const normalizedOrigin = origin.replace(/\/$/, '').toLowerCase();

  for (const allowed of config.allowedOrigins) {
    const normalizedAllowed = allowed.replace(/\/$/, '').toLowerCase();

    // Exact match
    if (normalizedOrigin === normalizedAllowed) {
      return true;
    }

    // Wildcard subdomain match (e.g., *.example.com)
    if (normalizedAllowed.startsWith('*.')) {
      const domain = normalizedAllowed.slice(2);
      if (normalizedOrigin.endsWith(domain) &&
          (normalizedOrigin === domain || normalizedOrigin.endsWith('.' + domain))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Generate CORS headers based on origin validation
 */
export function getCorsHeaders(
  requestOrigin: string | null,
  config: CorsConfig
): Record<string, string> {
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-admin-key, x-api-key',
    'Access-Control-Max-Age': '86400', // 24 hours
  };

  if (requestOrigin && validateOrigin(requestOrigin, config)) {
    headers['Access-Control-Allow-Origin'] = requestOrigin;
    if (config.allowCredentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
  }
  // If origin not valid, don't set Access-Control-Allow-Origin (browser will block)

  return headers;
}

/**
 * Sanitize string for safe logging (remove potential secrets/PII patterns)
 */
export function sanitizeForLogging(value: string, maxLength = 100): string {
  // Truncate
  let sanitized = value.slice(0, maxLength);
  if (value.length > maxLength) {
    sanitized += '...';
  }

  // Remove potential JWT tokens
  sanitized = sanitized.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, '[JWT]');

  // Remove potential API keys
  sanitized = sanitized.replace(/gk_[a-f0-9]{48}/gi, '[API_KEY]');

  // Remove potential UUIDs (might be user IDs)
  sanitized = sanitized.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '[UUID]');

  return sanitized;
}

/**
 * Rate limiting helper - extract identifier from request
 */
export function getRateLimitIdentifier(req: Request, userId?: string): string {
  if (userId) {
    return `user:${userId}`;
  }

  // Fall back to IP
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
             req.headers.get('x-real-ip') ||
             'unknown';
  return `ip:${ip}`;
}
