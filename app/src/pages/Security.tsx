import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  registerPasskey,
  listPasskeys,
  deletePasskey,
} from '../lib/webauthn';

/**
 * Security Settings Page
 *
 * Handles password management, session management, and passkey registration.
 */

interface Passkey {
  id: string;
  credential_id: string;
  device_name: string;
  authenticator_type: string;
  created_at: string;
  last_used_at: string | null;
  is_active: boolean;
}

export default function Security() {
  const { user } = useAuth();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Passkey state
  const [webAuthnSupported, setWebAuthnSupported] = useState(false);
  const [platformAuthAvailable, setPlatformAuthAvailable] = useState(false);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [loadingPasskeys, setLoadingPasskeys] = useState(true);
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState<string | null>(null);

  // Check WebAuthn support on mount
  useEffect(() => {
    const checkWebAuthn = async () => {
      setWebAuthnSupported(isWebAuthnSupported());
      const platformAvailable = await isPlatformAuthenticatorAvailable();
      setPlatformAuthAvailable(platformAvailable);
    };
    checkWebAuthn();
  }, []);

  // Load passkeys on mount
  useEffect(() => {
    loadPasskeys();
  }, []);

  const loadPasskeys = async () => {
    setLoadingPasskeys(true);
    const result = await listPasskeys();
    if (result.success && result.passkeys) {
      setPasskeys(result.passkeys);
    }
    setLoadingPasskeys(false);
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    try {
      setChangingPassword(true);

      const { error } = await supabase.auth.updateUser({
        password: newPassword,
      });

      if (error) throw error;

      setSuccess('Password updated successfully');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setChangingPassword(false);
    }
  };

  const handleRegisterPasskey = async () => {
    if (!user) return;

    setError(null);
    setSuccess(null);
    setRegisteringPasskey(true);

    const result = await registerPasskey(user.id, user.email || '', undefined);

    if (result.success) {
      setSuccess('Passkey registered successfully! You can now use biometrics to sign in.');
      await loadPasskeys();
    } else {
      setError(result.error || 'Failed to register passkey');
    }

    setRegisteringPasskey(false);
  };

  const handleDeletePasskey = async (passkeyId: string) => {
    if (!confirm('Are you sure you want to remove this passkey?')) {
      return;
    }

    setError(null);
    setDeletingPasskeyId(passkeyId);

    const result = await deletePasskey(passkeyId);

    if (result.success) {
      setSuccess('Passkey removed');
      await loadPasskeys();
    } else {
      setError(result.error || 'Failed to remove passkey');
    }

    setDeletingPasskeyId(null);
  };

  const handleSignOutAllDevices = async () => {
    if (!confirm('This will sign you out of all devices including this one. Continue?')) {
      return;
    }

    try {
      await supabase.auth.signOut({ scope: 'global' });
      window.location.href = '/login';
    } catch (err: any) {
      setError(err.message);
    }
  };

  const [deleting, setDeleting] = useState(false);

  const handleDeleteAccount = async () => {
    if (!confirm('This will permanently delete your Zule account and all associated data. This cannot be undone. Continue?')) {
      return;
    }
    if (!confirm('Are you absolutely sure? Your identity data will be permanently destroyed.')) {
      return;
    }

    setDeleting(true);
    setError(null);

    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) throw new Error('No active session');

      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/delete-account`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${session.access_token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to delete account');
      }

      await supabase.auth.signOut();
      window.location.href = '/login';
    } catch (err: any) {
      setError(err.message);
      setDeleting(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className="page-container">

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      {/* Passkeys Section */}
      <div className="card">
        <h2>Passkeys</h2>
        <p className="info-note">
          Use your device's biometrics (fingerprint or face) to sign in without a password.
        </p>

        {!webAuthnSupported ? (
          <div className="warning-message">
            Passkeys are not supported in this browser.
          </div>
        ) : !platformAuthAvailable ? (
          <div className="warning-message">
            Your device doesn't support biometric authentication.
          </div>
        ) : (
          <>
            {/* Registered Passkeys List */}
            {loadingPasskeys ? (
              <div className="loading-inline">Loading passkeys...</div>
            ) : passkeys.length > 0 ? (
              <div className="passkey-list">
                {passkeys.map((passkey) => (
                  <div key={passkey.id} className="passkey-item">
                    <div className="passkey-info">
                      <div className="passkey-name">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 512 512" style={{ width: '16px', height: '16px', flexShrink: 0 }}><path d="M19.75 14.438c59.538 112.29 142.51 202.35 232.28 292.718l3.626 3.75.063-.062c21.827 21.93 44.04 43.923 66.405 66.25-18.856 14.813-38.974 28.2-59.938 40.312l28.532 28.53 68.717-68.717c42.337 27.636 76.286 63.646 104.094 105.81l28.064-28.06c-42.47-27.493-79.74-60.206-106.03-103.876l68.936-68.938-28.53-28.53c-11.115 21.853-24.413 42.015-39.47 60.593-43.852-43.8-86.462-85.842-130.125-125.47-.224-.203-.432-.422-.656-.625C183.624 122.75 108.515 63.91 19.75 14.437zm471.875 0c-83.038 46.28-154.122 100.78-221.97 161.156l22.814 21.562 56.81-56.812 13.22 13.187-56.438 56.44 24.594 23.186c61.802-66.92 117.6-136.92 160.97-218.72zm-329.53 125.906 200.56 200.53a402.965 402.965 0 0 1-13.405 13.032L148.875 153.53l13.22-13.186zm-76.69 113.28-28.5 28.532 68.907 68.906c-26.29 43.673-63.53 76.414-106 103.907l28.063 28.06c27.807-42.164 61.758-78.174 104.094-105.81l68.718 68.717 28.53-28.53c-20.962-12.113-41.08-25.5-59.937-40.313 17.865-17.83 35.61-35.433 53.157-52.97l-24.843-25.655-55.47 55.467c-4.565-4.238-9.014-8.62-13.374-13.062l55.844-55.844-24.53-25.374c-18.28 17.856-36.602 36.06-55.158 54.594-15.068-18.587-28.38-38.758-39.5-60.625z"/></svg>
                        {passkey.device_name}
                      </div>
                      <div className="passkey-meta">
                        Added {formatDate(passkey.created_at)}
                        {passkey.last_used_at && (
                          <> • Last used {formatDate(passkey.last_used_at)}</>
                        )}
                      </div>
                    </div>
                    <button
                      className="btn-danger-small"
                      onClick={() => handleDeletePasskey(passkey.id)}
                      disabled={deletingPasskeyId === passkey.id}
                    >
                      {deletingPasskeyId === passkey.id ? 'Removing...' : 'Remove'}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-passkeys">
                No passkeys registered yet.
              </div>
            )}

            {/* Register New Passkey Button */}
            <button
              className="btn-primary"
              onClick={handleRegisterPasskey}
              disabled={registeringPasskey}
              style={{ marginTop: '16px' }}
            >
              {registeringPasskey ? 'Registering...' : 'Register New Passkey'}
            </button>
          </>
        )}
      </div>

      {/* Change Password */}
      <form onSubmit={handleChangePassword}>
        <div className="card">
          <h2>Change Password</h2>

          <div className="form-group">
            <label htmlFor="newPassword">New Password</label>
            <input
              type="password"
              id="newPassword"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password"
              minLength={8}
              autoComplete="new-password"
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm New Password</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              minLength={8}
              autoComplete="new-password"
            />
          </div>

          <button type="submit" className="btn-primary" disabled={changingPassword}>
            {changingPassword ? 'Updating...' : 'Update Password'}
          </button>
        </div>
      </form>

      {/* Session Management */}
      <div className="card">
        <h2>Sessions</h2>
        <p className="info-note">
          If you suspect unauthorized access to your account, sign out of all devices and change your password.
        </p>
        <button
          onClick={handleSignOutAllDevices}
          style={{ fontFamily: "'Cormorant Garamond', serif", fontSize: '14px', fontWeight: 500, letterSpacing: '0.06em', color: 'var(--text-secondary)', background: 'none', border: '1px solid var(--border)', padding: '6px 14px', borderRadius: '4px', cursor: 'pointer' }}
        >
          Sign Out All Devices
        </button>
        <div style={{ borderTop: '1px solid var(--border)', marginTop: '20px', paddingTop: '16px' }}>
          <p className="info-note" style={{ marginBottom: '12px' }}>
            Warning: this will delete your account and all personal information.
          </p>
          <button
            onClick={handleDeleteAccount}
            disabled={deleting}
            style={{ fontFamily: "'Cormorant Garamond', serif", fontSize: '14px', fontWeight: 500, letterSpacing: '0.06em', color: 'var(--text-secondary)', background: 'none', border: '1px solid var(--border)', padding: '6px 14px', borderRadius: '4px', cursor: 'pointer' }}
          >
            {deleting ? 'Deleting...' : 'Delete Account'}
          </button>
        </div>
      </div>

      {/* Account Info */}
      <div className="card">
        <h2>Account Information</h2>
        <div className="info-row">
          <span className="label">Email:</span>
          <span className="value">{user?.email}</span>
        </div>
        <div className="info-row">
          <span className="label">Account Created:</span>
          <span className="value">
            {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
          </span>
        </div>
        <div className="info-row">
          <span className="label">Last Sign In:</span>
          <span className="value">
            {user?.last_sign_in_at ? new Date(user.last_sign_in_at).toLocaleString() : 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );
}
