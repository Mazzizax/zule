/**
 * Centralized Rate Limiting for Zule Edge Functions
 *
 * Uses the existing check_rate_limit() PostgreSQL RPC which handles
 * atomic check + increment in a single call.
 *
 * Usage in any edge function:
 *   import { checkRateLimit } from '../_shared/rate-limit.ts'
 *   ...
 *   const blocked = await checkRateLimit(supabaseClient, req, 'function-name')
 *   if (blocked) return blocked
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { errorResponse } from './cors.ts'
import { getRateLimitIdentifier } from './security.ts'

interface RateLimitRule {
  /** Suffix appended to the action key (e.g. 'min', 'hr') */
  suffix: string
  /** Maximum requests allowed in the window */
  maxRequests: number
  /** Window duration in seconds */
  windowSeconds: number
}

/**
 * Per-endpoint rate limit configurations.
 *
 * Tiers:
 * - Auth (unauthenticated, brute-forceable): very strict
 * - Payment (real money): strict
 * - Data (authenticated CRUD): moderate
 * - Webhook (server-to-server, signature-verified): generous
 */
const ENDPOINT_LIMITS: Record<string, RateLimitRule[]> = {
  // ── Auth ─────────────────────────────────────────────
  'admin-auth': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 20, windowSeconds: 3600 },
  ],
  'auth-validate': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 20, windowSeconds: 3600 },
  ],
  'passkey-auth': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 60, windowSeconds: 3600 },
  ],
  'passkey-register': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 15, windowSeconds: 3600 },
  ],
  'mint-session': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
  ],
  'issue-attestation': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
  ],

  // ── Payment ──────────────────────────────────────────
  'create-checkout': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 20, windowSeconds: 3600 },
  ],
  'create-payment': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 20, windowSeconds: 3600 },
  ],
  'cancel-subscription': [
    { suffix: 'min', maxRequests: 3, windowSeconds: 60 },
  ],
  'upgrade-subscription': [
    { suffix: 'min', maxRequests: 3, windowSeconds: 60 },
  ],
  'create-portal-session': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
  ],
  'create-verification-session': [
    { suffix: 'min', maxRequests: 3, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 10, windowSeconds: 3600 },
  ],

  // ── Webhook (server-to-server, already signature-verified) ──
  'stripe-webhook': [
    { suffix: 'min', maxRequests: 100, windowSeconds: 60 },
  ],

  // ── Plaid ────────────────────────────────────────────
  'plaid-create-link-token': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
  ],
  'plaid-exchange-token': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
  ],
  'plaid-pull-transactions': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
    { suffix: 'hr', maxRequests: 30, windowSeconds: 3600 },
  ],
  'remove-card': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
  ],

  // ── Data CRUD ────────────────────────────────────────
  'loyalty-cards': [
    { suffix: 'min', maxRequests: 20, windowSeconds: 60 },
  ],
  'user-profile': [
    { suffix: 'min', maxRequests: 20, windowSeconds: 60 },
  ],
  'delete-account': [
    { suffix: 'hr', maxRequests: 1, windowSeconds: 3600 },
  ],

  // ── Enrichment ───────────────────────────────────────
  'mint-transaction-cards': [
    { suffix: 'min', maxRequests: 5, windowSeconds: 60 },
  ],
  'shred-minted-transactions': [
    { suffix: 'min', maxRequests: 3, windowSeconds: 60 },
  ],

  // ── App management ───────────────────────────────────
  'app-register': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
  ],
  'pair-client': [
    { suffix: 'min', maxRequests: 10, windowSeconds: 60 },
  ],
}

/** Fallback limits for any endpoint not explicitly configured */
const DEFAULT_LIMITS: RateLimitRule[] = [
  { suffix: 'min', maxRequests: 30, windowSeconds: 60 },
]

/**
 * Check rate limits for an edge function request.
 *
 * @param supabase - Service-role Supabase client
 * @param req - The incoming Request
 * @param functionName - The edge function name (e.g. 'create-checkout')
 * @param userId - Optional authenticated user ID (uses IP if not provided)
 * @returns null if allowed, or a 429 Response if rate limited
 */
export async function checkRateLimit(
  supabase: ReturnType<typeof createClient>,
  req: Request,
  functionName: string,
  userId?: string,
): Promise<Response | null> {
  const identifier = getRateLimitIdentifier(req, userId)
  const rules = ENDPOINT_LIMITS[functionName] || DEFAULT_LIMITS
  const origin = req.headers.get('Origin')

  for (const rule of rules) {
    const action = `${functionName}:${rule.suffix}`

    try {
      const { data, error } = await supabase.rpc('check_rate_limit', {
        p_identifier: identifier,
        p_action: action,
        p_max_requests: rule.maxRequests,
        p_window_seconds: rule.windowSeconds,
      })

      if (error) {
        // Fail open — don't block requests if rate limiting is broken
        console.error(`[RATE-LIMIT] RPC error for ${action}:`, error.message)
        continue
      }

      // check_rate_limit returns a single row: { allowed, current_count, reset_at }
      const result = Array.isArray(data) ? data[0] : data
      if (result && !result.allowed) {
        const resetAt = result.reset_at ? new Date(result.reset_at) : null
        const retryAfter = resetAt
          ? Math.max(1, Math.ceil((resetAt.getTime() - Date.now()) / 1000))
          : rule.windowSeconds

        console.warn(
          `[RATE-LIMIT] Blocked ${identifier} on ${action} ` +
          `(${result.current_count}/${rule.maxRequests}, retry in ${retryAfter}s)`
        )

        // Log to audit_logs for security monitoring
        await supabase.from('audit_logs').insert({
          user_id: userId || null,
          action: 'rate_limited',
          action_category: 'security',
          ip_address: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || null,
          metadata: {
            function: functionName,
            rule: action,
            count: result.current_count,
            limit: rule.maxRequests,
            window_seconds: rule.windowSeconds,
          },
          success: false,
          error_message: 'Rate limit exceeded',
        }).catch(() => { /* don't fail the response over audit logging */ })

        return errorResponse(
          'Too many requests. Please try again later.',
          429,
          origin,
        )
      }
    } catch (err) {
      // Fail open
      console.error(`[RATE-LIMIT] Exception for ${action}:`, err)
    }
  }

  return null // All checks passed
}
