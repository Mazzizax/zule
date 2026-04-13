import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const { signUp } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !password || !confirmPassword) {
      setError('Please fill in all fields');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await signUp(email, password);
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'Could not create account');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="auth-header">
            <h1>CHECK YOUR EMAIL</h1>
            <p>We sent a verification link to {email}</p>
          </div>
          <div className="success-message">
            Click the link in your email to verify your account, then come back to sign in.
          </div>
          <button className="btn-primary" onClick={() => navigate('/login')}>
            Back to Login
          </button>
        </div>
      </div>
    );
  }

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
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          {error && <div className="error-message">{error}</div>}

          <div className="form-group">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              autoComplete="new-password"
            />
          </div>

          <div className="form-group">
            <input
              type="password"
              placeholder="Confirm Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              disabled={loading}
              autoComplete="new-password"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating account...' : 'Create Account'}
          </button>

          <div className="auth-footer">
            <p>
              Already have an account? <Link to="/login">Sign In</Link>
            </p>
            <p style={{ marginTop: '16px', fontSize: '11px', opacity: 0.5, textAlign: 'center' }}>
              <a href="/privacy" onClick={(e) => { e.preventDefault(); window.open('/privacy', 'privacy', 'width=580,height=700,left=200,top=100'); }}>Privacy</a> · <a href="/terms" onClick={(e) => { e.preventDefault(); window.open('/terms', 'terms', 'width=580,height=700,left=200,top=100'); }}>Terms</a>
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
