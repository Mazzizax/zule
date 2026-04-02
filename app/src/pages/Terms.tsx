import React from 'react';

export default function Terms() {
  return (
    <div className="legal-page">
      <div className="legal-container">
        <h1>Terms of Service</h1>
        <p className="legal-updated">Last updated: March 20, 2026</p>

        <h2>Agreement</h2>
        <p>
          By creating an account or using any part of the platform &mdash; including Zule, Vinzrik,
          and Goals &mdash; you agree to these terms. If you don&apos;t agree, don&apos;t use the platform.
        </p>

        <h2>What We Provide</h2>
        <p>
          Zule is part of a rewards and engagement platform for every lifestyle. You can
          link a financial account to automatically track gear purchases, earn XP, complete quests,
          and engage with brand-sponsored challenges &mdash; all through an anonymous identity that
          cannot be linked back to your real identity by any system in our architecture.
        </p>

        <h2>Your Account</h2>
        <p>
          You&apos;re responsible for keeping your login credentials secure. If you use passkey/biometric
          authentication, access is tied to your physical device. We can&apos;t recover your anonymous
          game identity if you lose access to your device &mdash; the cryptographic secret that links
          your account to your game data exists only on your device&apos;s hardware keystore.
        </p>

        <h2>Financial Account Linking</h2>
        <p>
          When you link a financial account through Plaid, you authorize us to receive read-only
          transaction data. We use this data solely to identify products, award XP, match sponsor
          reward pools, and advance quests. We do not access your balances, move money, or store
          your bank credentials. Raw financial details (dollar amounts, dates, locations) are
          permanently deleted immediately after processing. See our{' '}
          <a href="/privacy" onClick={(e) => { e.preventDefault(); window.open('/privacy', 'privacy', 'width=580,height=700,left=200,top=100'); }}>Privacy Policy</a> for
          full details.
        </p>

        <h2>Your Content and Data</h2>
        <p>
          Your game data (XP, gear, quests, loadouts) is stored under an anonymous identity.
          Your real identity data (email, credentials) is stored separately. You own your data.
          You can request deletion of your account and all associated data at any time.
        </p>

        <h2>Sponsors and Brands</h2>
        <p>
          Brands may sponsor reward pools and quests on the platform. By participating in
          sponsored challenges, you may earn bonus XP and rewards. Sponsors receive only
          aggregate, anonymous engagement data &mdash; they never receive your identity, email,
          or individual purchase information.
        </p>

        <h2>Acceptable Use</h2>
        <p>
          Don&apos;t attempt to reverse-engineer the anonymous identity system, manipulate XP or
          rewards through fraudulent transactions, or abuse the platform in ways that harm
          other users or sponsors. We reserve the right to suspend accounts that violate these terms.
        </p>

        <h2>Disclaimers</h2>
        <p>
          The platform is provided as-is. We don&apos;t guarantee uninterrupted service. XP, rewards,
          and gear condition values are game mechanics and have no cash value. We may modify
          game mechanics, reward rates, or sponsor pool configurations at any time.
        </p>

        <h2>Changes to These Terms</h2>
        <p>
          We may update these terms. If we make significant changes, we&apos;ll notify you through
          the platform. Continued use after changes means you accept the updated terms.
        </p>

        <h2>Contact</h2>
        <p><a href="https://mazzizax.org/contact">mazzizax.org/contact</a></p>

        <p className="legal-entity">Mazz Ink, LLC &mdash; Illinois, USA</p>
      </div>
    </div>
  );
}
