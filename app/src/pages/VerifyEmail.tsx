import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';

export default function VerifyEmail() {
  const { user, resendVerification, signOut, refreshUser, emailVerified } = useAuth();
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [checking, setChecking] = useState(false);

  // When tab regains focus, refresh user to pick up verification
  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        refreshUser();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, [refreshUser]);

  // Auto-redirect when verified
  useEffect(() => {
    if (emailVerified) {
      window.location.href = '/';
    }
  }, [emailVerified]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const handleCheckVerification = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      await refreshUser();
      // If still not verified after refresh, show message
      // (emailVerified effect above handles the redirect if verified)
      setTimeout(() => {
        setChecking(false);
        setError('Email not verified yet. Check your inbox.');
      }, 500);
    } catch (err: any) {
      setError(err.message || 'Failed to check verification status');
      setChecking(false);
    }
  }, [refreshUser]);

  const handleResend = async () => {
    setSending(true);
    setError(null);
    setSent(false);

    try {
      await resendVerification();
      setSent(true);
      setCooldown(60);
    } catch (err: any) {
      setError(err.message || 'Failed to send verification email');
    } finally {
      setSending(false);
    }
  };

  const handleBackToLogin = async () => {
    await signOut();
    window.location.href = '/login';
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1 style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400 }}>
            <span className="metal-text" style={{ display: 'inline-block' }}>V</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>E</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>R</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>I</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>F</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>Y</span>
          </h1>
          <p>email verification required</p>
        </div>

        <div className="success-message">
          A verification link was sent to <strong>{user?.email}</strong>.
          Check your inbox and click the link to continue.
        </div>

        {error && <div className="error-message">{error}</div>}

        {sent && !error && (
          <div className="success-message" style={{ marginTop: '12px' }}>
            Verification email sent. Check your inbox.
          </div>
        )}

        <div className="auth-form" style={{ gap: '12px' }}>
          <button
            className="btn-primary"
            onClick={handleResend}
            disabled={sending || cooldown > 0}
          >
            {sending
              ? 'Sending...'
              : cooldown > 0
                ? `Resend in ${cooldown}s`
                : 'Resend Verification Email'}
          </button>

          <button
            className="btn-primary"
            onClick={handleCheckVerification}
            disabled={checking}
            style={{ background: '#2a5a8a' }}
          >
            {checking ? 'Checking...' : "I've Verified My Email"}
          </button>

          <button
            className="btn-secondary"
            onClick={handleBackToLogin}
            style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}
          >
            Back to Login
          </button>
        </div>
      </div>
    </div>
  );
}
