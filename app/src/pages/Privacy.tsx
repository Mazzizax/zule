import React from 'react';

export default function Privacy() {
  return (
    <div className="legal-page">
      <div className="legal-container">
        <h1>Privacy Policy</h1>
        <p className="legal-updated">Last updated: March 20, 2026</p>

        <h2>What We Collect and Why</h2>
        <p>
          Zule is part of a rewards and engagement platform. When you link a financial account through Plaid,
          we receive read-only transaction data &mdash; merchant name, amount, date, category, and location &mdash;
          for one purpose: to identify products and services you purchase so we can populate your gear inventory,
          award XP, match sponsor reward pools, and advance quests.
        </p>
        <p>We do not build budgeting tools, display spending summaries, or retain financial records.</p>

        <h2>How We Handle Your Data</h2>
        <p>
          Transaction data is processed by our enrichment service the moment it arrives. The dollar amount
          is converted to XP. The merchant and description are used to identify the product and match
          sponsor pools. The date is converted to an obfuscated timestamp. The location is reduced to a
          yes/no verification. The raw financial data &mdash; dollar amounts, dates, and locations &mdash; is
          permanently deleted immediately after processing.
        </p>
        <p>
          What survives is game data: product name, brand, merchant, equipment slot, XP awards,
          and activity classification. This game data is passed to our rewards platform attached to an
          anonymous identity that cannot be linked back to you.
        </p>

        <h2>Architectural Privacy</h2>
        <p>
          Your real identity (email, credentials, payment info) and your game activity (XP, gear, quests)
          are stored in completely separate databases with no shared identifiers. The only link between them
          is a cryptographic secret on your physical device that never leaves your phone&apos;s hardware keystore.
          No single system in our architecture can connect who you are to what you do.
        </p>

        <h2>What We Do Not Do</h2>
        <ul>
          <li>We do not sell your data.</li>
          <li>We do not share your identity with sponsors or brands.</li>
          <li>We do not store credit card numbers &mdash; Stripe handles all payment processing.</li>
          <li>We do not store bank login credentials &mdash; Plaid handles all institution authentication.</li>
          <li>We do not retain raw transaction data beyond the moment of processing.</li>
          <li>We do not access your balances, account numbers, or transfer capabilities.</li>
        </ul>

        <h2>Plaid</h2>
        <p>
          We use Plaid to connect to your financial institution. When you link an account,
          you authenticate directly with your bank through Plaid&apos;s secure widget &mdash; your bank credentials
          are never shared with us. We request only the <strong>transactions</strong> product &mdash;
          read-only access to transaction history. We do not request access to balances, identity
          information, or money movement capabilities. You can disconnect your account at any time
          from the Zule dashboard.
        </p>

        <h2>Sponsors and Brands</h2>
        <p>
          Brands can sponsor reward pools and quests on the platform. They see aggregate, anonymous
          engagement data &mdash; for example, how many users are using their products or how many times a
          reward pool has been claimed. They never receive your email, name, purchase amounts, or any
          information that could identify you in the real world.
        </p>

        <h2>Your Rights</h2>
        <p>
          You can delete your account at any time from the Security page in your Zule dashboard.
          When your account is deleted, all of your identity and personal data in Zule is permanently removed.
          Ownership of anonymized game data (XP, gear records, quest history) that is abandoned
          upon account deletion is transferred to Mazz Ink&apos;s in-game account.
        </p>

        <h2>Security</h2>
        <p>
          All data is encrypted at rest (AES-256) and in transit (TLS 1.2+). Authentication supports
          WebAuthn passkeys with biometric verification. Our infrastructure providers (Supabase, Vercel,
          Stripe, Plaid) maintain SOC 2 Type 2 certifications.
        </p>

        <h2>Contact</h2>
        <p><a href="https://mazzizax.org/contact">mazzizax.org/contact</a></p>

        <p className="legal-entity">Mazz Ink, LLC &mdash; Illinois, USA</p>
      </div>
    </div>
  );
}
