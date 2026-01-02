/**
 * Shared dependencies for Gatekeeper Edge Functions
 */

export { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
export { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
export {
  encode as base64Encode,
  decode as base64Decode
} from 'https://deno.land/std@0.168.0/encoding/base64.ts';
