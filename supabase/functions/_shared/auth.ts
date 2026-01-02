/**
 * Authentication utilities for Gatekeeper
 */

import { createClient } from './deps.ts';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

export interface AuthenticatedUser {
  id: string;
  email?: string;
  tier: string;
  features: Record<string, unknown>;
  isSuspended: boolean;
}

/**
 * Authenticate request and return user info
 */
export async function authenticateRequest(req: Request): Promise<{
  user: AuthenticatedUser | null;
  error: string | null;
}> {
  const authHeader = req.headers.get('authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return { user: null, error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.split(' ')[1];
  const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

  // Verify the JWT
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);

  if (authError || !user) {
    return { user: null, error: 'Invalid or expired token' };
  }

  // Get user profile with tier info
  const { data: profile, error: profileError } = await supabase
    .rpc('get_user_tier_info', { p_user_id: user.id });

  if (profileError) {
    console.error('[AUTH] Profile lookup error:', profileError);
    // Default to free tier if profile lookup fails
    return {
      user: {
        id: user.id,
        email: user.email,
        tier: 'free',
        features: {},
        isSuspended: false,
      },
      error: null,
    };
  }

  const tierInfo = profile?.[0] || {
    tier: 'free',
    status: 'active',
    features: {},
    is_suspended: false,
  };

  return {
    user: {
      id: user.id,
      email: user.email,
      tier: tierInfo.tier,
      features: tierInfo.features || {},
      isSuspended: tierInfo.is_suspended,
    },
    error: null,
  };
}

/**
 * Extract client info from request
 */
export function getClientInfo(req: Request): {
  ipAddress: string | null;
  userAgent: string | null;
} {
  return {
    ipAddress: req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
               req.headers.get('x-real-ip') ||
               null,
    userAgent: req.headers.get('user-agent'),
  };
}
