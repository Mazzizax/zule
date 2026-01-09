import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { supabase } from '../lib/supabase';

/**
 * Auth Page for Dawg Tag
 *
 * This page handles authentication requests from Dawg Tag.
 * Flow:
 * 1. Dawg Tag opens: /auth?callback=dawgtag://auth-callback
 * 2. User logs in with email/password
 * 3. On success, call issue-attestation to get signed JWT
 * 4. Redirect to callback with attestation (NOT user_id)
 *
 * The attestation proves "a valid user authenticated" without revealing identity.
 *
 * This is specifically for the Dawg Tag auth flow.
 */

export default function Auth() {
  const [searchParams] = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirecting, setRedirecting] = useState(false);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  // Get callback URL
  const callbackUrl = searchParams.get('callback');

  // Validate callback URL
  const isValidCallback = callbackUrl && (
    callbackUrl.startsWith('dawgtag://') ||
    callbackUrl.startsWith('exp://') || // Expo development
    callbackUrl.startsWith('https://')
  );

  // Handle redirect after successful auth
  useEffect(() => {
    if (redirectUrl) {
      console.log('[AUTH] Attempting redirect to:', redirectUrl);

      // For custom schemes on mobile, try multiple approaches
      if (redirectUrl.startsWith('dawgtag://') || redirectUrl.startsWith('exp://')) {
        // Try iframe first (works better on iOS Safari)
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = redirectUrl;
        document.body.appendChild(iframe);

        // Then try direct location change
        setTimeout(() => {
          window.location.href = redirectUrl;
        }, 500);

        // Clean up iframe after attempt
        setTimeout(() => {
          if (iframe.parentNode) {
            iframe.parentNode.removeChild(iframe);
          }
        }, 2000);
      } else {
        // Standard HTTPS redirect
        window.location.href = redirectUrl;
      }
    }
  }, [redirectUrl]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!isValidCallback) {
      setError('Invalid callback URL');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Authenticate with Supabase
      const { data, error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (authError) {
        throw authError;
      }

      if (!data.user || !data.session) {
        throw new Error('Login failed - no user or session returned');
      }

      // Call issue-attestation edge function to get signed JWT
      const { data: attestationData, error: attestationError } = await supabase.functions.invoke(
        'issue-attestation',
        {
          headers: {
            Authorization: `Bearer ${data.session.access_token}`,
          },
        }
      );

      if (attestationError) {
        throw new Error(`Attestation failed: ${attestationError.message}`);
      }

      if (!attestationData?.attestation) {
        throw new Error('No attestation returned');
      }

      // Build callback URL with attestation (NOT user_id)
      const finalRedirectUrl = new URL(callbackUrl!);
      finalRedirectUrl.searchParams.set('attestation', attestationData.attestation);
      finalRedirectUrl.searchParams.set('status', 'success');

      // Sign out from web session (we only needed to get the attestation)
      await supabase.auth.signOut();

      // Set state to trigger redirect
      setRedirecting(true);
      setRedirectUrl(finalRedirectUrl.toString());
    } catch (err: any) {
      setError(err.message || 'Login failed');
      setLoading(false);
    }
  };

  const handleCancel = () => {
    if (callbackUrl) {
      const cancelUrl = new URL(callbackUrl);
      cancelUrl.searchParams.set('status', 'cancelled');
      setRedirecting(true);
      setRedirectUrl(cancelUrl.toString());
    }
  };

  // Show error if no valid callback
  if (!isValidCallback) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <h1>GATEKEEPER</h1>
            <p>Authentication Error</p>
          </div>
          <div className="error-message">
            Invalid or missing callback URL. This page should be opened from Dawg Tag.
          </div>
        </div>
      </div>
    );
  }

  // Show redirecting message
  if (redirecting) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <h1>GATEKEEPER</h1>
            <p>Redirecting to Dawg Tag...</p>
          </div>
          <div style={{ textAlign: 'center', padding: '24px' }}>
            <div className="loading-spinner" style={{ margin: '0 auto 16px' }} />
            <p style={{ color: '#666', fontSize: '14px' }}>
              If you're not redirected automatically,{' '}
              <a
                href={redirectUrl || '#'}
                style={{ color: '#4CAF50' }}
                onClick={(e) => {
                  e.preventDefault();
                  if (redirectUrl) window.location.href = redirectUrl;
                }}
              >
                click here
              </a>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1>GATEKEEPER</h1>
          <p>Sign in to continue to your app</p>
        </div>

        {error && <div className="error-message">{error}</div>}

        <form className="auth-form" onSubmit={handleLogin}>
          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              disabled={loading}
              autoComplete="email"
              autoFocus
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
              autoComplete="current-password"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <button
          className="btn-secondary"
          onClick={handleCancel}
          disabled={loading}
          style={{ marginTop: '16px' }}
        >
          Cancel
        </button>

        <div style={{ marginTop: '24px', textAlign: 'center' }}>
          <p style={{ color: '#666', fontSize: '12px' }}>
            Your credentials are verified by Gatekeeper.
            <br />
            Your identity stays private with Dawg Tag.
          </p>
        </div>
      </div>
    </div>
  );
}
