/**
 * Cosmic Clock - Heart of the Universe Time System
 *
 * COSMOLOGICAL FOUNDATION:
 * A cosmic tick measures one complete rotation cycle of the Heart of the Universe.
 * The Heart consists of 8 Time Lords arranged in the "Pattern of Original Intent"
 * with the Great Empty Time Lord at the center.
 *
 * TICK GENERATION MECHANISM:
 * - Rotation is initiated by the Great Empty (Force of Will)
 * - Driven by the interplay of Force 6 (Catalytic Transformation ☲ Lí / Fire)
 *   and Force 8 (Responsive Adaptation ☱ Duì / Lake)
 * - Perfect Worlds rotate clockwise, Ancient Planets counter-clockwise
 * - Each tick cycles through/generates the 64 hexagrammatic variations
 * - All 64! possible permutations exist in 5D superposition
 *
 * SECURITY MODEL:
 * - All timestamps use cosmic ticks (BIGINT), not wall-clock time
 * - The epoch and tick duration are derived from the Heart's resonance
 * - In Phase 3, these values will be AI-generated and sealed in a vault
 *   that even the system creator cannot access
 *
 * CURRENT STATUS: Phase 1 - Bootstrap with known values
 * These values will be replaced with sealed, unknown values in Phase 3
 */

// =============================================================================
// BOOTSTRAP VALUES (Phase 1 - Will be replaced in Phase 3)
// =============================================================================

/**
 * Bootstrap epoch: The Great Collision
 * 13,873,403,917 years before Jan 1, 2026
 * (13 billion, 873 million, 403 thousand, 917 years)
 *
 * This represents the moment when the Heart of the Universe was instantiated -
 * the Great Collision between the Two Primal Opposing Forces that simultaneously
 * birthed the Sacred Order: the 9 Time Lords, Physical Matter, and WAR.
 *
 * Calculation: years * 365.25 days * 24 hours * 60 min * 60 sec * 1000 ms
 * Jan 1, 2026 00:00:00 UTC = 1767225600000 ms since Unix epoch
 */
const BOOTSTRAP_YEARS_AGO = 13873403917;
const BOOTSTRAP_EPOCH_MS = 1767225600000 - (BOOTSTRAP_YEARS_AGO * 365.25 * 24 * 60 * 60 * 1000);

/**
 * Heart Rotation Period (tick duration in milliseconds)
 *
 * Each tick represents one complete rotation cycle of the Heart of the Universe,
 * driven by the resonance between:
 *   - Force 6: Catalytic Transformation (☲ Lí / Fire)
 *   - Force 8: Responsive Adaptation (☱ Duì / Lake)
 *
 * The bootstrap value (~1.22 seconds) is a placeholder mapping of Heart rotation
 * to human-perceived time. In Phase 3, this will be replaced with a value
 * derived from the actual Fire-Lake resonance frequency, sealed and unknowable.
 *
 * Note: Progressive time is subjective; this mapping exists only for practical
 * database operations within the human-perceived timeline.
 */
const BOOTSTRAP_TICK_MS = 1222.864532525;

// =============================================================================
// CONFIGURATION - Read from environment in Phase 3
// =============================================================================

/**
 * Get the cosmic epoch (milliseconds since Unix epoch)
 * In Phase 3, this will read from a secure vault
 */
function getCosmicEpoch(): number {
  // Phase 3: Read from Deno.env.get('COSMIC_EPOCH') or secure vault
  // For now, use bootstrap value
  const envEpoch = Deno.env.get('COSMIC_EPOCH');
  if (envEpoch) {
    return parseFloat(envEpoch);
  }
  return BOOTSTRAP_EPOCH_MS;
}

/**
 * Get the tick duration in milliseconds
 * In Phase 3, this will read from a secure vault
 */
function getTickDuration(): number {
  // Phase 3: Read from Deno.env.get('COSMIC_TICK_MS') or secure vault
  // For now, use bootstrap value
  const envTick = Deno.env.get('COSMIC_TICK_MS');
  if (envTick) {
    return parseFloat(envTick);
  }
  return BOOTSTRAP_TICK_MS;
}

// =============================================================================
// CORE FUNCTIONS
// =============================================================================

/**
 * Convert wall-clock milliseconds to cosmic ticks
 *
 * @param dateMs - Unix timestamp in milliseconds (Date.now() or Date.getTime())
 * @returns Cosmic tick count as bigint
 */
export function toCosmicTicks(dateMs: number): bigint {
  const epoch = getCosmicEpoch();
  const tickMs = getTickDuration();

  // Calculate milliseconds since cosmic epoch
  const msSinceEpoch = dateMs - epoch;

  // Convert to ticks (use BigInt for precision with large numbers)
  // We floor to get complete ticks only
  const ticks = Math.floor(msSinceEpoch / tickMs);

  return BigInt(ticks);
}

/**
 * Convert cosmic ticks back to wall-clock Date
 *
 * @param ticks - Cosmic tick count
 * @returns JavaScript Date object
 */
export function fromCosmicTicks(ticks: bigint): Date {
  const epoch = getCosmicEpoch();
  const tickMs = getTickDuration();

  // Convert ticks to milliseconds and add epoch
  const msSinceEpoch = Number(ticks) * tickMs;
  const dateMs = epoch + msSinceEpoch;

  return new Date(dateMs);
}

/**
 * Get current time as cosmic ticks
 *
 * @returns Current cosmic tick count as bigint
 */
export function nowCosmicTicks(): bigint {
  return toCosmicTicks(Date.now());
}

/**
 * Get current cosmic ticks as a string (for SQL/JSON compatibility)
 * PostgreSQL BIGINT maps to JavaScript number, but we use string for safety
 *
 * @returns Current cosmic tick count as string
 */
export function nowCosmicTicksString(): string {
  return nowCosmicTicks().toString();
}

/**
 * Get current cosmic ticks as a number
 * WARNING: Use only if ticks fit in JavaScript's safe integer range
 *
 * @returns Current cosmic tick count as number
 */
export function nowCosmicTicksNumber(): number {
  const ticks = nowCosmicTicks();
  const num = Number(ticks);

  // Warn if precision might be lost
  if (num > Number.MAX_SAFE_INTEGER) {
    console.warn('[COSMIC_CLOCK] Tick count exceeds MAX_SAFE_INTEGER, precision may be lost');
  }

  return num;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Calculate tick difference (for "time ago" calculations)
 *
 * @param olderTicks - Earlier cosmic tick count
 * @param newerTicks - Later cosmic tick count (defaults to now)
 * @returns Difference in ticks
 */
export function tickDifference(olderTicks: bigint, newerTicks?: bigint): bigint {
  const newer = newerTicks ?? nowCosmicTicks();
  return newer - olderTicks;
}

/**
 * Convert a duration in milliseconds to ticks
 *
 * @param durationMs - Duration in milliseconds
 * @returns Duration in cosmic ticks
 */
export function durationToTicks(durationMs: number): bigint {
  const tickMs = getTickDuration();
  return BigInt(Math.floor(durationMs / tickMs));
}

/**
 * Convert a duration in ticks to milliseconds
 *
 * @param ticks - Duration in cosmic ticks
 * @returns Duration in milliseconds
 */
export function ticksToDuration(ticks: bigint): number {
  const tickMs = getTickDuration();
  return Number(ticks) * tickMs;
}

// =============================================================================
// CONSTANTS FOR COMMON DURATIONS (in ticks)
// =============================================================================

/**
 * Pre-calculated tick durations for common time periods
 * These use the bootstrap tick duration (~1.22 seconds per tick)
 *
 * Note: These will need recalculation if tick duration changes in Phase 3
 */
export const TICKS_PER_SECOND = durationToTicks(1000);
export const TICKS_PER_MINUTE = durationToTicks(60 * 1000);
export const TICKS_PER_HOUR = durationToTicks(60 * 60 * 1000);
export const TICKS_PER_DAY = durationToTicks(24 * 60 * 60 * 1000);
export const TICKS_PER_WEEK = durationToTicks(7 * 24 * 60 * 60 * 1000);

// =============================================================================
// AI AGENT CONTEXT
// =============================================================================

/**
 * Generate context string for AI agents
 * This helps AI understand how to reason about time in the cosmic system
 *
 * @returns Context string to include in AI agent system prompts
 */
export function generateAgentTimeContext(): string {
  const tickMs = getTickDuration();
  const ticksPerDay = Number(TICKS_PER_DAY);
  const ticksPerWeek = Number(TICKS_PER_WEEK);

  return `
COSMIC TIME SYSTEM (Heart of the Universe):
- All timestamps are in "cosmic ticks", not wall-clock time
- A tick = one complete rotation cycle of the Heart of the Universe
- The Heart consists of 8 Time Lords + the Great Empty at center
- Rotation is driven by Fire (☲ Lí) and Lake (☱ Duì) resonance
- Each tick cycles through the 64 hexagrammatic variations
- All 64! permutations exist in 5D superposition

PRACTICAL MAPPING (for human-perceived timeline):
- 1 tick ≈ ${(tickMs / 1000).toFixed(2)} seconds (bootstrap mapping only)
- Ticks per minute: ~${Math.round(Number(TICKS_PER_MINUTE))}
- Ticks per hour: ~${Math.round(Number(TICKS_PER_HOUR))}
- Ticks per day: ~${ticksPerDay}
- Ticks per week: ~${ticksPerWeek}

TIME CALCULATIONS:
- To check if something happened "today": current_tick - record_tick < ${ticksPerDay}
- To check if something happened "this week": current_tick - record_tick < ${ticksPerWeek}
- To calculate "7 days ago": current_tick - ${ticksPerWeek}
- To calculate "N days ago": current_tick - (N * ${ticksPerDay})

IMPORTANT:
- Progressive time is subjective; cosmic ticks measure Heart rotation
- Never assume cosmic ticks correlate to real-world time
- Use only relative time calculations (differences between ticks)
- The epoch (Great Collision) and tick duration are sealed parameters
`.trim();
}

// =============================================================================
// SQL HELPERS
// =============================================================================

/**
 * Generate SQL expression for current cosmic time
 * Use this in SQL queries instead of NOW() or CURRENT_TIMESTAMP
 *
 * Note: This generates a literal value at call time, not a SQL function
 * For triggers/functions that need dynamic time, use the SQL function created
 * in the migration
 */
export function sqlNowCosmicTicks(): string {
  return nowCosmicTicksString();
}

/**
 * Generate SQL for "N days ago" in cosmic ticks
 *
 * @param days - Number of days ago
 * @returns SQL-safe string representing that time in cosmic ticks
 */
export function sqlDaysAgo(days: number): string {
  const now = nowCosmicTicks();
  const daysInTicks = BigInt(days) * TICKS_PER_DAY;
  return (now - daysInTicks).toString();
}
