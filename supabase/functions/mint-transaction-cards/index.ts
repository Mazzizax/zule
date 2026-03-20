/**
 * Zule: Enrich & Mint Transaction Cards
 *
 * The enrichment service. Converts raw Plaid transactions into game event
 * cards for Goals. Zule is the ONLY service that sees real-world data.
 *
 * For each unminted transaction:
 * 1. Match against active sponsor pools (rule-based)
 * 2. Match against quest templates (fetched from Goals)
 * 3. Identify gear via Gemini 2.5 Flash
 * 4. Convert dollars → XP (base rate + sponsor multipliers)
 * 5. Build game event card (zero financial data)
 * 6. Sign as ES256 JWT, mark minted
 *
 * Output: signed JWT containing GameEventCard[] — no dollars, no merchants,
 * no descriptions. Goals receives pure game events.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { handleCors, jsonResponse, errorResponse } from '../_shared/cors.ts'
import { toCosmicTicks, nowCosmicTicksNumber } from '../_shared/cosmic-clock.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const ZULE_CARD_SIGNING_KEY = Deno.env.get('ZULE_CARD_SIGNING_KEY')!
const GOOGLE_API_KEY = Deno.env.get('GOOGLE_API_KEY')!
const GOALS_URL = Deno.env.get('GOALS_URL') || 'https://goals.mazzizax.com'

// Base XP rate: $1 = 1 base XP
const BASE_XP_PER_DOLLAR = 1

interface RawTransaction {
  id: string
  merchant_name: string | null
  amount: number
  date: string
  category: string | null
  subcategory: string | null
  location_city: string | null
  location_state: string | null
}

interface SponsorPool {
  id: string
  pool_slug: string
  match_conditions: MatchCondition[]
  reward_tags: RewardTags
  budget_max_claims: number | null
  budget_max_per_user: number
  claims_used: number
}

interface MatchCondition {
  type: 'merchant' | 'category' | 'keyword' | 'amount'
  op: 'contains' | 'equals' | 'any_of' | 'gte' | 'lte'
  value?: string | number
  values?: string[]
}

interface RewardTags {
  xp_bonus: number
  xp_multiplier: number
  gear_category?: string
  activity_tag?: string
  badge_slug?: string
}

interface QuestTemplate {
  id: string
  display_name: string
  match_criteria: {
    gear_categories?: string[]
    activity_tags?: string[]
    is_outdoor_recreation?: boolean
  }
}

interface GearIdentification {
  product_name: string
  brand: string
  category: string
  suggested_slot: string
  activity_types: string[]
}

interface GameEventCard {
  cosmic_tick: string
  xp_awards: {
    purchase_xp: number
    sponsor_xp: number
    quest_xp: number
  }
  gear: GearIdentification | null
  pool_hits: string[]
  quest_template_hits: string[]
  activity_tag: string | null
  is_outdoor_recreation: boolean
  location_verified: boolean
}

// =============================================================================
// CRYPTO — ES256 JWT signing (preserved from original mint function)
// =============================================================================

async function importSigningKey(keyStr: string): Promise<CryptoKey> {
  try {
    const jwk = JSON.parse(keyStr)
    return await crypto.subtle.importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
    )
  } catch { /* fall through to PEM */ }

  const pemContents = keyStr
    .replace(/-----BEGIN EC PRIVATE KEY-----/g, '')
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END EC PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '')

  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0))
  return await crypto.subtle.importKey(
    'pkcs8', binaryDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  )
}

function base64url(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function signCardsJwt(cards: GameEventCard[], privateKey: CryptoKey): Promise<string> {
  const header = { alg: 'ES256', typ: 'JWT' }
  const payload = {
    iss: 'zule',
    aud: 'goals',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    cards,
  }

  const encoder = new TextEncoder()
  const headerB64 = base64url(encoder.encode(JSON.stringify(header)))
  const payloadB64 = base64url(encoder.encode(JSON.stringify(payload)))
  const signable = `${headerB64}.${payloadB64}`

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    encoder.encode(signable)
  )

  return `${signable}.${base64url(new Uint8Array(signature))}`
}

// =============================================================================
// SPONSOR POOL MATCHING (rule-based v1)
// =============================================================================

function evaluateCondition(condition: MatchCondition, tx: RawTransaction): boolean {
  const { type, op } = condition

  switch (type) {
    case 'merchant': {
      const merchant = (tx.merchant_name || '').toLowerCase()
      if (op === 'contains') return merchant.includes((condition.value as string || '').toLowerCase())
      if (op === 'equals') return merchant === (condition.value as string || '').toLowerCase()
      return false
    }
    case 'category': {
      const category = (tx.subcategory || tx.category || '').toLowerCase()
      if (op === 'contains') return category.includes((condition.value as string || '').toLowerCase())
      if (op === 'equals') return category === (condition.value as string || '').toLowerCase()
      return false
    }
    case 'keyword': {
      const text = `${tx.merchant_name || ''} ${tx.category || ''} ${tx.subcategory || ''}`.toLowerCase()
      if (op === 'any_of' && condition.values) {
        return condition.values.some(kw => text.includes(kw.toLowerCase()))
      }
      if (op === 'contains') return text.includes((condition.value as string || '').toLowerCase())
      return false
    }
    case 'amount': {
      const amount = Math.abs(tx.amount)
      if (op === 'gte') return amount >= (condition.value as number || 0)
      if (op === 'lte') return amount <= (condition.value as number || 0)
      return false
    }
    default:
      return false
  }
}

function matchPool(pool: SponsorPool, tx: RawTransaction): boolean {
  // ALL conditions must match (AND logic)
  return pool.match_conditions.every(cond => evaluateCondition(cond, tx))
}

// =============================================================================
// QUEST TEMPLATE MATCHING
// =============================================================================

let cachedTemplates: QuestTemplate[] | null = null
let templateCacheTime = 0
const TEMPLATE_CACHE_TTL = 60_000 // 1 minute

async function fetchQuestTemplates(): Promise<QuestTemplate[]> {
  const now = Date.now()
  if (cachedTemplates && (now - templateCacheTime) < TEMPLATE_CACHE_TTL) {
    return cachedTemplates
  }

  try {
    const res = await fetch(`${GOALS_URL}/functions/v1/publish-quest-templates`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!res.ok) {
      console.error('[ENRICH] Failed to fetch quest templates:', res.status)
      return cachedTemplates || []
    }

    const data = await res.json()
    cachedTemplates = data.templates || []
    templateCacheTime = now
    return cachedTemplates!
  } catch (err) {
    console.error('[ENRICH] Quest template fetch error:', err)
    return cachedTemplates || []
  }
}

function matchQuestTemplates(gear: GearIdentification | null, activityTag: string | null, isOutdoor: boolean, templates: QuestTemplate[]): string[] {
  const hits: string[] = []

  for (const tmpl of templates) {
    const criteria = tmpl.match_criteria
    let matched = false

    // Match by gear category
    if (criteria.gear_categories && gear) {
      if (criteria.gear_categories.some(gc => gc.toLowerCase() === gear.category.toLowerCase())) {
        matched = true
      }
    }

    // Match by activity tag
    if (criteria.activity_tags && activityTag) {
      if (criteria.activity_tags.some(at => at.toLowerCase() === activityTag.toLowerCase())) {
        matched = true
      }
    }

    // Match by outdoor recreation flag
    if (criteria.is_outdoor_recreation && isOutdoor) {
      matched = true
    }

    if (matched) hits.push(tmpl.id)
  }

  return hits
}

// =============================================================================
// GEAR IDENTIFICATION (Gemini-powered, same prompt as Goals gear-search)
// =============================================================================

const BATCH_GEAR_PROMPT = `You are a product classifier. Given a JSON array of transactions, classify each one.

For each transaction, determine:
- Is it a gear/product purchase? (not groceries, gas, dining, subscriptions, bills)
- If yes: product_name, brand, category, suggested_slot, activity_types, activity_tag, is_outdoor_recreation
- If no: is_gear: false, activity_tag if applicable, is_outdoor_recreation

Slot options: head, face, eyewear, earbuds, neck, shoulders, chest, back, arms, hands, waist, legs, feet, ring_1, ring_2, watch, pack, bottle, poles, gps

Return a JSON array with one result per transaction, in the same order. No markdown, no code blocks, just raw JSON array:
[
  {"idx":0,"is_gear":false},
  {"idx":1,"is_gear":true,"product_name":"...","brand":"...","category":"...","suggested_slot":"...","activity_types":["..."],"activity_tag":"...","is_outdoor_recreation":true},
  ...
]`;

interface BatchGearResult {
  idx: number
  is_gear: boolean
  product_name?: string
  brand?: string
  category?: string
  suggested_slot?: string
  activity_types?: string[]
  activity_tag?: string
  is_outdoor_recreation?: boolean
}

async function batchIdentifyGear(transactions: RawTransaction[]): Promise<Map<number, { gear: GearIdentification | null, activityTag: string | null, isOutdoor: boolean }>> {
  const results = new Map<number, { gear: GearIdentification | null, activityTag: string | null, isOutdoor: boolean }>()

  // Default all to no gear
  for (let i = 0; i < transactions.length; i++) {
    results.set(i, { gear: null, activityTag: null, isOutdoor: false })
  }

  if (!GOOGLE_API_KEY || transactions.length === 0) return results

  try {
    const txArray = transactions.map((tx, i) => ({
      idx: i,
      merchant: tx.merchant_name || 'Unknown',
      category: tx.subcategory || tx.category || '',
    }))

    const prompt = BATCH_GEAR_PROMPT + '\n\nTransactions:\n' + JSON.stringify(txArray)

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${GOOGLE_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 8192 },
        }),
      }
    )

    if (!response.ok) {
      console.error('[ENRICH] Gemini batch API error:', response.status)
      return results
    }

    const data = await response.json()
    const textContent = data.candidates?.[0]?.content?.parts
      ?.filter((p: { text?: string }) => p.text)
      ?.map((p: { text: string }) => p.text)
      ?.join('') || ''

    if (!textContent) return results

    // Parse JSON array
    let jsonStr = textContent
    const jsonMatch = textContent.match(/```(?:json)?\s*([\s\S]*?)\s*```/)
    if (jsonMatch) jsonStr = jsonMatch[1]

    const arrStart = jsonStr.indexOf('[')
    const arrEnd = jsonStr.lastIndexOf(']')
    if (arrStart === -1 || arrEnd === -1) return results

    const parsed: BatchGearResult[] = JSON.parse(jsonStr.slice(arrStart, arrEnd + 1))

    for (const item of parsed) {
      if (item.idx === undefined || item.idx < 0 || item.idx >= transactions.length) continue

      if (item.is_gear && item.product_name) {
        results.set(item.idx, {
          gear: {
            product_name: item.product_name,
            brand: item.brand || '',
            category: item.category || '',
            suggested_slot: item.suggested_slot || 'pack',
            activity_types: Array.isArray(item.activity_types) ? item.activity_types : [],
          },
          activityTag: item.activity_tag || null,
          isOutdoor: item.is_outdoor_recreation || false,
        })
      } else {
        results.set(item.idx, {
          gear: null,
          activityTag: item.activity_tag || null,
          isOutdoor: item.is_outdoor_recreation || false,
        })
      }
    }
  } catch (err) {
    console.error('[ENRICH] Batch gear identification error:', err)
  }

  return results
}

// =============================================================================
// MAIN HANDLER
// =============================================================================

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin')

  const preflight = handleCors(req)
  if (preflight) return preflight

  if (req.method !== 'POST') {
    return errorResponse('Method not allowed', 405, origin)
  }

  try {
    // 1. AUTHENTICATE via Zule JWT
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return errorResponse('Missing authorization header', 401, origin)
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
      global: { headers: { Authorization: authHeader } },
    })

    const { data: { user }, error: authError } = await supabase.auth.getUser()
    if (authError || !user) {
      console.error('[ENRICH] Auth error:', authError?.message)
      return errorResponse('Invalid or expired token', 401, origin)
    }

    // 2. FETCH UNMINTED TRANSACTIONS
    const adminClient = createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })

    const { data: unminted, error: fetchError } = await adminClient
      .from('user_transactions')
      .select('id, merchant_name, amount, date, category, subcategory, location_city, location_state')
      .eq('user_id', user.id)
      .eq('minted', false)

    if (fetchError) {
      console.error('[ENRICH] Fetch error:', fetchError)
      return errorResponse('Failed to fetch transactions', 500, origin)
    }

    if (!unminted || unminted.length === 0) {
      return jsonResponse({ card_attestation: null, card_count: 0, message: 'No unminted transactions' }, 200, origin)
    }

    // 3. FETCH ENRICHMENT CONTEXT (parallel)
    const currentTick = nowCosmicTicksNumber()

    const [activePools, questTemplates] = await Promise.all([
      // Fetch active sponsor pools
      adminClient
        .from('sponsor_pools')
        .select('id, pool_slug, match_conditions, reward_tags, budget_max_claims, budget_max_per_user, claims_used')
        .eq('is_active', true)
        .lte('campaign_start', currentTick)
        .gte('campaign_end', currentTick)
        .then(r => (r.data || []) as SponsorPool[]),

      // Fetch quest templates from Goals
      fetchQuestTemplates(),
    ])

    // 4. BATCH GEAR IDENTIFICATION (one Gemini call for all transactions)
    const gearResults = await batchIdentifyGear(unminted as RawTransaction[])

    // 5. ENRICH EACH TRANSACTION
    const cards: GameEventCard[] = []
    const mintedIds: string[] = []
    const poolClaimsToInsert: Array<{ pool_id: string, user_id: string, transaction_id: string, xp_awarded: number }> = []
    const poolClaimCounts: Record<string, number> = {}

    for (let txIdx = 0; txIdx < unminted.length; txIdx++) {
      const tx = unminted[txIdx] as RawTransaction
      const cosmicTick = toCosmicTicks(new Date(tx.date + 'T00:00:00Z').getTime())
      const locationVerified = !!(tx.location_city || tx.location_state)

      const { gear, activityTag, isOutdoor } = gearResults.get(txIdx) || { gear: null, activityTag: null, isOutdoor: false }

      // --- Sponsor pool matching ---
      const poolHits: string[] = []
      let sponsorXp = 0

      for (const pool of activePools) {
        // Budget check
        const totalClaimed = pool.claims_used + (poolClaimCounts[pool.id] || 0)
        if (pool.budget_max_claims !== null && totalClaimed >= pool.budget_max_claims) continue

        if (matchPool(pool, tx)) {
          const tags = pool.reward_tags as RewardTags
          const bonus = tags.xp_bonus || 0
          const multiplier = tags.xp_multiplier || 1

          const xpFromPool = Math.round(bonus * multiplier)
          sponsorXp += xpFromPool
          poolHits.push(pool.pool_slug)

          poolClaimsToInsert.push({
            pool_id: pool.id,
            user_id: user.id,
            transaction_id: tx.id,
            xp_awarded: xpFromPool,
          })

          poolClaimCounts[pool.id] = (poolClaimCounts[pool.id] || 0) + 1
        }
      }

      // --- Quest template matching ---
      const questHits = matchQuestTemplates(gear, activityTag, isOutdoor, questTemplates)
      const questXp = questHits.length > 0 ? 25 * questHits.length : 0

      // --- XP computation ---
      const purchaseXp = Math.round(Math.abs(tx.amount) * BASE_XP_PER_DOLLAR)

      // --- Build game event card ---
      // Use activity tag from sponsor pool if available
      const finalActivityTag = activityTag ||
        (poolHits.length > 0 ? (activePools.find(p => p.pool_slug === poolHits[0])?.reward_tags as RewardTags)?.activity_tag : null) ||
        null

      cards.push({
        cosmic_tick: cosmicTick.toString(),
        xp_awards: {
          purchase_xp: purchaseXp,
          sponsor_xp: sponsorXp,
          quest_xp: questXp,
        },
        gear,
        pool_hits: poolHits,
        quest_template_hits: questHits,
        activity_tag: finalActivityTag,
        is_outdoor_recreation: isOutdoor,
        location_verified: locationVerified,
      })

      mintedIds.push(tx.id)
    }

    // 5. RECORD POOL CLAIMS
    if (poolClaimsToInsert.length > 0) {
      const { error: claimError } = await adminClient
        .from('pool_claims')
        .insert(poolClaimsToInsert)

      if (claimError) {
        console.error('[ENRICH] Pool claims insert error:', claimError)
      } else {
        // Update claims_used counters
        for (const [poolId, count] of Object.entries(poolClaimCounts)) {
          await adminClient.rpc('increment_pool_claims', { p_pool_id: poolId, p_count: count })
            .then(r => { if (r.error) console.error('[ENRICH] Pool counter update error:', r.error) })
        }
      }
    }

    // 6. SIGN CARDS AS JWT
    const signingKey = await importSigningKey(ZULE_CARD_SIGNING_KEY)
    const cardAttestation = await signCardsJwt(cards, signingKey)

    // 7. MARK ROWS AS MINTED
    const { error: updateError } = await adminClient
      .from('user_transactions')
      .update({ minted: true, minted_at: new Date().toISOString() })
      .in('id', mintedIds)

    if (updateError) {
      console.error('[ENRICH] Failed to mark transactions as minted:', updateError)
    }

    console.log(`[ENRICH] User ${user.id.substring(0, 8)}...: enriched ${cards.length} cards (${poolClaimsToInsert.length} pool claims, ${cards.filter(c => c.gear).length} gear items)`)

    // 8. RETURN ATTESTATION
    return jsonResponse({
      card_attestation: cardAttestation,
      card_count: cards.length,
    }, 200, origin)

  } catch (error) {
    console.error('[ENRICH] Error:', error)
    return errorResponse('Internal server error', 500, origin)
  }
})
