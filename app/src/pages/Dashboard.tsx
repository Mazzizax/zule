import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../lib/supabase';

/** Get a fresh access token from the Supabase client */
async function getFreshToken(): Promise<string | null> {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.access_token ?? null;
}

/**
 * Dashboard - Account Overview
 *
 * NOTE: Ghost ID display has been moved to Vinzrik.
 * This dashboard now shows account info, subscription status,
 * and connected financial accounts (Plaid).
 * Zule knows WHO you are, Vinzrik handles app connections.
 */

interface ProfileSummary {
  subscription_tier: string;
  subscription_status: string;
  subscription_expires_at: string | null;
  created_at: string;
  last_seen_at: string;
  plaid_institution_name: string | null;
  plaid_connected_at: string | null;
}

export default function Dashboard() {
  const { user, session } = useAuth();
  const [profile, setProfile] = useState<ProfileSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [plaidLoading, setPlaidLoading] = useState(false);
  const [pullLoading, setPullLoading] = useState(false);
  const [pullResult, setPullResult] = useState<string | null>(null);

  useEffect(() => {
    if (session?.access_token) {
      fetchProfile();
    }
  }, [session]);

  const fetchProfile = async () => {
    const token = await getFreshToken();
    if (!token) return;

    try {
      setLoading(true);
      const response = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/user-profile`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );

      if (!response.ok) {
        throw new Error('Failed to fetch profile');
      }

      const data = await response.json();
      setProfile(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString();
  };

  const openPlaidLink = async () => {
    const token = await getFreshToken();
    if (!token) return;

    setPlaidLoading(true);
    try {
      // 1. Get link_token from backend
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/plaid-create-link-token`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to create link token');
      }

      const { link_token } = await res.json();

      // 2. Open Plaid Link widget
      const Plaid = (window as any).Plaid;
      if (!Plaid) {
        throw new Error('Plaid Link not loaded. Please refresh the page.');
      }

      const handler = Plaid.create({
        token: link_token,
        onSuccess: async (public_token: string) => {
          try {
            const exchangeToken = await getFreshToken();
            await fetch(
              `${import.meta.env.ZULE_URL}/functions/v1/plaid-exchange-token`,
              {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${exchangeToken}`,
                  'Content-Type': 'application/json',
                  'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
                },
                body: JSON.stringify({ public_token }),
              }
            );
            fetchProfile(); // Refresh to show connected status
          } catch (err) {
            console.error('Token exchange failed:', err);
            setError('Failed to connect account. Please try again.');
          }
        },
        onExit: () => {
          setPlaidLoading(false);
        },
      });

      handler.open();
    } catch (err: any) {
      setError(err.message);
      setPlaidLoading(false);
    }
  };

  const pullTransactions = async () => {
    const token = await getFreshToken();
    if (!token) return;

    setPullLoading(true);
    setPullResult(null);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/plaid-pull-transactions`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to pull transactions');
      }

      const data = await res.json();
      setPullResult(`Synced: +${data.added} new, ~${data.modified} updated, -${data.removed} removed`);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setPullLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="loading-spinner" />
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Dashboard</h1>
        <p>Your Zule account overview</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      {/* Privacy Notice */}
      <div className="privacy-banner">
        <span className="privacy-icon">🔒</span>
        <div>
          <strong>Privacy by Design</strong>
          <p>Zule manages your identity. Your app connections and activity are handled by Vinzrik on your device.</p>
        </div>
      </div>

      <div className="card-grid">
        {/* Account Info */}
        <div className="card">
          <h2>Account</h2>
          <div className="info-row">
            <span className="label">Email:</span>
            <span className="value">{user?.email}</span>
          </div>
          <div className="info-row">
            <span className="label">Member Since:</span>
            <span className="value">{formatDate(profile?.created_at || user?.created_at || null)}</span>
          </div>
          <div className="info-row">
            <span className="label">Last Active:</span>
            <span className="value">{formatDate(profile?.last_seen_at || null)}</span>
          </div>
        </div>

        {/* Subscription Info */}
        <div className="card">
          <h2>Subscription</h2>
          <div className="info-row">
            <span className="label">Tier:</span>
            <span className="value tier-badge">{profile?.subscription_tier || 'free'}</span>
          </div>
          <div className="info-row">
            <span className="label">Status:</span>
            <span className={`value status-${profile?.subscription_status || 'active'}`}>
              {profile?.subscription_status || 'Active'}
            </span>
          </div>
          {profile?.subscription_expires_at && (
            <div className="info-row">
              <span className="label">Renews:</span>
              <span className="value">{formatDate(profile.subscription_expires_at)}</span>
            </div>
          )}
        </div>
      </div>

      {/* Connected Accounts (Plaid) */}
      <div className="card">
        <h2>Connected Accounts</h2>
        {profile?.plaid_institution_name ? (
          <>
            <div className="info-row">
              <span className="label">Card:</span>
              <span className="value">{profile.plaid_institution_name}</span>
            </div>
            <div className="info-row">
              <span className="label">Connected:</span>
              <span className="value">{formatDate(profile.plaid_connected_at)}</span>
            </div>
            <div className="info-row">
              <span className="label">Status:</span>
              <span className="value status-active">Connected</span>
            </div>
            <div style={{ marginTop: '16px' }}>
              <button
                className="btn-secondary"
                onClick={pullTransactions}
                disabled={pullLoading}
              >
                {pullLoading ? 'Pulling...' : 'Pull Latest Transactions'}
              </button>
              {pullResult && (
                <div className="success-message" style={{ marginTop: '12px' }}>
                  {pullResult}
                </div>
              )}
            </div>
            <div className="info-note" style={{ marginTop: '12px' }}>
              <p>Transactions are stored in Zule. Use Vinzrik to sync them to Goals (anonymized via your ghost identity).</p>
            </div>
          </>
        ) : (
          <>
            <div className="info-note">
              <p>Link your card to track spending on your quests. Transaction data stays in Zule and is only relayed to Goals through Vinzrik, anonymized with your ghost identity.</p>
            </div>
            <div style={{ marginTop: '16px' }}>
              <button
                className="btn-primary"
                onClick={openPlaidLink}
                disabled={plaidLoading}
              >
                {plaidLoading ? 'Connecting...' : 'Link Card'}
              </button>
            </div>
          </>
        )}
      </div>

      {/* Vinzrik Notice */}
      <div className="card">
        <h2>App Connections</h2>
        <div className="info-note">
          <p>
            Your app connections and ghost identity are managed by <strong>Vinzrik</strong> on your device.
            This ensures that even Zule cannot see which apps you use or link your identity to your activity.
          </p>
          <p style={{ marginTop: '0.5rem', opacity: 0.7 }}>
            Open Vinzrik to view and manage your connected apps.
          </p>
        </div>
      </div>
    </div>
  );
}
