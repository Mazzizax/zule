import React from 'react';

export default function Terms() {
  return (
    <div className="auth-container" style={{ padding: '40px 20px', maxWidth: '720px', margin: '0 auto' }}>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', marginBottom: '4px' }}>Terms of Service</h1>
        <p style={{ fontSize: '12px', opacity: 0.5 }}>Effective March 20, 2026 — Mazz Ink</p>
      </div>

      <div style={{ fontSize: '14px', lineHeight: '1.7', color: '#ccc' }}>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Agreement</h2>
        <p>
          By creating an account or using any part of the Mazzizax platform — including Zule, Vinzrik,
          and Goals — you agree to these terms. If you don't agree, don't use the platform.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>What We Provide</h2>
        <p>
          Mazzizax is a rewards and engagement platform for outdoor and athletic lifestyle. You can
          link a financial account to automatically track gear purchases, earn XP, complete quests,
          and engage with brand-sponsored challenges — all through an anonymous identity that
          cannot be linked back to your real identity by any system in our architecture.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Your Account</h2>
        <p>
          You're responsible for keeping your login credentials secure. If you use passkey/biometric
          authentication, access is tied to your physical device. We can't recover your anonymous
          game identity if you lose access to your device — the cryptographic secret that links
          your account to your game data exists only on your device's hardware keystore.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Financial Account Linking</h2>
        <p>
          When you link a financial account through Plaid, you authorize us to receive read-only
          transaction data. We use this data solely to identify products, award XP, match sponsor
          reward pools, and advance quests. We do not access your balances, move money, or store
          your bank credentials. Raw financial details (dollar amounts, dates, locations) are
          permanently deleted immediately after processing. See our <a href="/privacy" style={{ color: '#d4a' }}>Privacy Policy</a> for
          full details.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Your Content and Data</h2>
        <p>
          Your game data (XP, gear, quests, loadouts) is stored under an anonymous identity.
          Your real identity data (email, credentials) is stored separately. You own your data.
          You can request deletion of your account and all associated data at any time.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Sponsors and Brands</h2>
        <p>
          Brands may sponsor reward pools and quests on the platform. By participating in
          sponsored challenges, you may earn bonus XP and rewards. Sponsors receive only
          aggregate, anonymous engagement data — they never receive your identity, email,
          or individual purchase information.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Acceptable Use</h2>
        <p>
          Don't attempt to reverse-engineer the anonymous identity system, manipulate XP or
          rewards through fraudulent transactions, or abuse the platform in ways that harm
          other users or sponsors. We reserve the right to suspend accounts that violate these terms.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Disclaimers</h2>
        <p>
          The platform is provided as-is. We don't guarantee uninterrupted service. XP, rewards,
          and gear condition values are game mechanics and have no cash value. We may modify
          game mechanics, reward rates, or sponsor pool configurations at any time.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Changes to These Terms</h2>
        <p>
          We may update these terms. If we make significant changes, we'll notify you through
          the platform. Continued use after changes means you accept the updated terms.
        </p>

        <h2 style={{ fontSize: '16px', color: '#fff', marginTop: '24px', marginBottom: '8px' }}>Contact</h2>
        <p>
          Brian Mazzuckelli — <a href="mailto:b.mazz@mazzizax.com" style={{ color: '#d4a' }}>b.mazz@mazzizax.com</a>
        </p>

      </div>
    </div>
  );
}
