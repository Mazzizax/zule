import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function Privacy() {
  const navigate = useNavigate();

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.85)', zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '20px',
    }} onClick={() => navigate(-1)}>
      <div style={{
        background: '#111', border: '1px solid #333', borderRadius: '8px',
        maxWidth: '680px', width: '100%', maxHeight: '85vh', overflowY: 'auto',
        padding: '32px', position: 'relative',
      }} onClick={e => e.stopPropagation()}>
        <button onClick={() => navigate(-1)} style={{
          position: 'absolute', top: '12px', right: '16px',
          background: 'none', border: 'none', color: '#666', fontSize: '20px', cursor: 'pointer',
        }}>&times;</button>

        <h1 style={{ fontSize: '20px', marginBottom: '4px' }}>Privacy Policy</h1>
        <p style={{ fontSize: '11px', opacity: 0.4, marginBottom: '24px' }}>Effective March 20, 2026 — Mazz Ink</p>

        <div style={{ fontSize: '13px', lineHeight: '1.7', color: '#bbb' }}>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>What We Collect and Why</h2>
          <p>
            Mazzizax is a rewards and engagement platform. When you link a financial account through Plaid,
            we receive read-only transaction data — merchant name, amount, date, category, and location —
            for one purpose: to identify products you purchase so we can populate your gear inventory,
            award XP, match sponsor reward pools, and advance quests.
          </p>
          <p style={{ marginTop: '10px' }}>
            We do not build budgeting tools, display spending summaries, or retain financial records.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>How We Handle Your Data</h2>
          <p>
            Transaction data is processed by our enrichment service the moment it arrives. The dollar amount
            is converted to XP. The merchant and description are used to identify the product and match
            sponsor pools. The date is converted to an obfuscated timestamp. The location is reduced to a
            yes/no verification. The raw financial data — dollar amounts, dates, and locations — is
            permanently deleted immediately after processing.
          </p>
          <p style={{ marginTop: '10px' }}>
            What survives is game data: product name, brand, merchant, equipment slot, XP awards,
            and activity classification. This game data is passed to our rewards platform attached to an
            anonymous identity that cannot be linked back to you.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Architectural Privacy</h2>
          <p>
            Your real identity (email, credentials, payment info) and your game activity (XP, gear, quests)
            are stored in completely separate databases with no shared identifiers. The only link between them
            is a cryptographic secret on your physical device that never leaves your phone's hardware keystore.
            No single system in our architecture can connect who you are to what you do.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>What We Do Not Do</h2>
          <ul style={{ paddingLeft: '18px', marginTop: '6px' }}>
            <li>We do not sell your data.</li>
            <li>We do not share your identity with sponsors or brands.</li>
            <li>We do not store credit card numbers — Stripe handles all payment processing.</li>
            <li>We do not store bank login credentials — Plaid handles all institution authentication.</li>
            <li>We do not retain raw transaction data beyond the moment of processing.</li>
            <li>We do not access your balances, account numbers, or transfer capabilities.</li>
          </ul>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Plaid</h2>
          <p>
            We use Plaid to connect to your financial institution. When you link an account,
            you authenticate directly with your bank through Plaid's secure widget — your bank credentials
            are never shared with us. We request only the <strong>transactions</strong> product —
            read-only access to transaction history. We do not request access to balances, identity
            information, or money movement capabilities. You can disconnect your account at any time
            from the Zule dashboard.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Sponsors and Brands</h2>
          <p>
            Brands can sponsor reward pools and quests on the platform. They see aggregate, anonymous
            engagement data — for example, how many users are using their products or how many times a
            reward pool has been claimed. They never receive your email, name, purchase amounts, or any
            information that could identify you individually.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Your Rights</h2>
          <p>
            You can request deletion of your account and all associated data at any time by contacting
            us at <a href="mailto:b.mazz@mazzizax.com" style={{ color: '#d4a' }}>b.mazz@mazzizax.com</a>.
            When your account is deleted, your identity data in Zule and your game data in Goals
            are both permanently removed.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Security</h2>
          <p>
            All data is encrypted at rest (AES-256) and in transit (TLS 1.2+). Authentication supports
            WebAuthn passkeys with biometric verification. Our infrastructure providers (Supabase, Vercel,
            Stripe, Plaid) maintain SOC 2 Type 2 certifications.
          </p>

          <h2 style={{ fontSize: '14px', color: '#fff', marginTop: '20px', marginBottom: '6px' }}>Contact</h2>
          <p>
            Brian Mazzuckelli — <a href="mailto:b.mazz@mazzizax.com" style={{ color: '#d4a' }}>b.mazz@mazzizax.com</a>
          </p>

        </div>
      </div>
    </div>
  );
}
