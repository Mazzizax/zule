import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';
import { clearGhostIdentity } from '../lib/ghostKeys';

export default function Security() {
  const { user, signOut } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    try {
      setChangingPassword(true);

      const { error } = await supabase.auth.updateUser({
        password: newPassword,
      });

      if (error) throw error;

      setSuccess('Password updated successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setChangingPassword(false);
    }
  };

  const handleSignOutAllDevices = async () => {
    if (!confirm('This will sign you out of all devices including this one. Continue?')) {
      return;
    }

    try {
      // Sign out from Supabase (this invalidates all sessions)
      await supabase.auth.signOut({ scope: 'global' });
      clearGhostIdentity();
      window.location.href = '/login';
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleResetGhostIdentity = async () => {
    if (!confirm('WARNING: This will generate a new ghost_id. Apps will see you as a completely new user and you will lose access to any data associated with your current ghost_id. This cannot be undone. Are you sure?')) {
      return;
    }

    if (!confirm('This is your last chance. All your app data will become inaccessible. Type "RESET" to confirm.')) {
      return;
    }

    const confirmation = prompt('Type RESET to confirm:');
    if (confirmation !== 'RESET') {
      return;
    }

    try {
      // Clear the ghost secret - next login will generate a new one
      clearGhostIdentity();
      await signOut();
      window.location.href = '/login';
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Security</h1>
        <p>Manage your account security settings</p>
      </div>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

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
              minLength={6}
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
              minLength={6}
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
          If you suspect unauthorized access to your account, you can sign out of all devices.
        </p>
        <button className="btn-secondary" onClick={handleSignOutAllDevices}>
          Sign Out All Devices
        </button>
      </div>

      {/* Danger Zone */}
      <div className="card danger-zone">
        <h2>Danger Zone</h2>

        <div className="danger-item">
          <div>
            <h3>Reset Ghost Identity</h3>
            <p>
              Generate a new ghost_id. Apps will see you as a completely new user.
              All data associated with your current ghost_id will become inaccessible.
            </p>
          </div>
          <button className="btn-danger" onClick={handleResetGhostIdentity}>
            Reset Ghost Identity
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
