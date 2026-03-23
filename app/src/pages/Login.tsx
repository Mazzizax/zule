import React, { useState, useEffect } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  authenticateWithPasskey,
} from '../lib/webauthn';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // WebAuthn state
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [platformAuthAvailable, setPlatformAuthAvailable] = useState(false);

  // Check for callback URL (from Vinzrik)
  const callbackUrl = searchParams.get('callback');
  const appId = searchParams.get('app_id');

  // Check WebAuthn support on mount
  useEffect(() => {
    const checkWebAuthn = async () => {
      const supported = isWebAuthnSupported();
      setWebAuthnSupported(supported);
      if (supported) {
        const platformAvailable = await isPlatformAuthenticatorAvailable();
        setPlatformAuthAvailable(platformAvailable);
      }
    };
    checkWebAuthn();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !password) {
      setError('Please enter email and password');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await signIn(email, password);

      // If there's a callback URL, handle it
      if (callbackUrl) {
        // TODO: Generate token and redirect to callback
        // For now, just navigate to dashboard
        navigate('/');
      } else {
        navigate('/');
      }
    } catch (err: any) {
      setError(err.message || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setPasskeyLoading(true);
    setError(null);

    try {
      const result = await authenticateWithPasskey();

      if (result.success && result.userId) {
        // If there's a callback URL, redirect with token
        if (callbackUrl) {
          // TODO: Generate secure token and redirect
          // For now, redirect with user_id (NOT SECURE - needs token implementation)
          const redirectUrl = new URL(callbackUrl);
          redirectUrl.searchParams.set('user_id', result.userId);
          redirectUrl.searchParams.set('tier', result.tier || 'free');
          if (appId) {
            redirectUrl.searchParams.set('app_id', appId);
          }
          window.location.href = redirectUrl.toString();
        } else {
          // No callback - this is direct web login
          // Passkey auth doesn't create a session, so redirect to email/password
          setError('Passkey verified, but no callback URL provided. Please use email/password to sign in to the dashboard.');
        }
      } else {
        setError(result.error || 'Passkey authentication failed');
      }
    } catch (err: any) {
      setError(err.message || 'Passkey authentication failed');
    } finally {
      setPasskeyLoading(false);
    }
  };

  const canUsePasskey = webAuthnSupported && platformAuthAvailable;

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <h1 style={{ fontFamily: "'Cormorant Garamond', serif", fontWeight: 400 }}>
            <span className="metal-text" style={{ display: 'inline-block' }}>Z</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>U</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>L</span>
            <span className="metal-text" style={{ display: 'inline-block' }}>E</span>
          </h1>
          <p>
            {callbackUrl
              ? 'Sign in to continue to your app'
              : 'Sign in to your account'
            }
          </p>
        </div>

        {/* Passkey Login (Primary option when available) */}
        {canUsePasskey && (
          <>
            <button
              className="btn-passkey"
              onClick={handlePasskeyLogin}
              disabled={passkeyLoading || loading}
            >
              {passkeyLoading ? (
                'Authenticating...'
              ) : (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 512 512" style={{ width: '18px', height: '18px' }}><path d="M19.75 14.438c59.538 112.29 142.51 202.35 232.28 292.718l3.626 3.75.063-.062c21.827 21.93 44.04 43.923 66.405 66.25-18.856 14.813-38.974 28.2-59.938 40.312l28.532 28.53 68.717-68.717c42.337 27.636 76.286 63.646 104.094 105.81l28.064-28.06c-42.47-27.493-79.74-60.206-106.03-103.876l68.936-68.938-28.53-28.53c-11.115 21.853-24.413 42.015-39.47 60.593-43.852-43.8-86.462-85.842-130.125-125.47-.224-.203-.432-.422-.656-.625C183.624 122.75 108.515 63.91 19.75 14.437zm471.875 0c-83.038 46.28-154.122 100.78-221.97 161.156l22.814 21.562 56.81-56.812 13.22 13.187-56.438 56.44 24.594 23.186c61.802-66.92 117.6-136.92 160.97-218.72zm-329.53 125.906 200.56 200.53a402.965 402.965 0 0 1-13.405 13.032L148.875 153.53l13.22-13.186zm-76.69 113.28-28.5 28.532 68.907 68.906c-26.29 43.673-63.53 76.414-106 103.907l28.063 28.06c27.807-42.164 61.758-78.174 104.094-105.81l68.718 68.717 28.53-28.53c-20.962-12.113-41.08-25.5-59.937-40.313 17.865-17.83 35.61-35.433 53.157-52.97l-24.843-25.655-55.47 55.467c-4.565-4.238-9.014-8.62-13.374-13.062l55.844-55.844-24.53-25.374c-18.28 17.856-36.602 36.06-55.158 54.594-15.068-18.587-28.38-38.758-39.5-60.625z"/></svg>
                  Sign in with Passkey
                </>
              )}
            </button>

            <div className="auth-divider">
              <span>or use email</span>
            </div>
          </>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          {error && <div className="error-message">{error}</div>}

          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading || passkeyLoading}
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading || passkeyLoading}
              autoComplete="current-password"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading || passkeyLoading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>

          <div className="auth-footer" style={{ position: 'relative', paddingBottom: '16px', borderBottom: '1px solid var(--border)' }}>
            <p>
              Don't have an account? <Link to="/register">Create Account</Link>
            </p>
            <p style={{ position: 'absolute', bottom: '-8px', left: '50%', transform: 'translateX(-50%)', fontSize: '11px', opacity: 0.5, background: 'var(--bg-card)', padding: '0 12px' }}>
              <Link to="/privacy">Privacy</Link> · <Link to="/terms">Terms</Link>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
