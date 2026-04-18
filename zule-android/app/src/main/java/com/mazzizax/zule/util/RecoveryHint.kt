package com.mazzizax.zule.util

/**
 * Taxonomy of actionable error states. Each hint maps to a specific
 * recovery UI affordance (re-enrol, retry with Google Password Manager,
 * open device security settings, contact support). Consumers dispatch on
 * this enum rather than parsing error strings.
 */
enum class RecoveryHint {
    FORCE_REENROLL,
    ALREADY_ENROLLED,
    RETRY_WITH_GOOGLE_PM,
    NEEDS_SCREEN_LOCK,
    CONTACT_SUPPORT,
}
