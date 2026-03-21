import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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

interface PlaidAccount {
  id: string;
  institution_name: string;
  connected_at: string;
}

interface Subscription {
  service_id: string;
  tier: string;
  status: string;
  stripe_subscription_id: string | null;
  expires_at: string | null;
}

interface ProfileSummary {
  subscription_tier: string;
  subscription_status: string;
  subscription_expires_at: string | null;
  created_at: string;
  last_seen_at: string;
  plaid_institution_name: string | null;
  plaid_connected_at: string | null;
  plaid_accounts: PlaidAccount[];
  subscriptions: Subscription[];
}

const SERVICE_DISPLAY_NAME: Record<string, string> = {
  goals: 'Goals',
  aca: 'Advanced Cognitive Assistant',
};

const metals: Record<string, { gradient: string, border: string, shadow: string, text: string, highlight: string }> = {
  rose: {
    gradient: 'linear-gradient(145deg, #8a7560 0%, #C4A882 15%, #E0D0B8 30%, #D4BC9A 45%, #A08968 55%, #C4A882 70%, #E0D0B8 85%, #8a7560 100%)',
    border: 'rgba(224,208,184,0.4)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.25), inset 0 -1px 0 rgba(0,0,0,0.3), 0 2px 4px rgba(0,0,0,0.5), 0 1px 0 rgba(196,168,130,0.15)',
    text: '#1a1510',
    highlight: 'rgba(224,208,184,0.4)',
  },
  titanium: {
    gradient: 'linear-gradient(145deg, #7a8590 0%, #B0BEC5 15%, #CFD8DC 30%, #B0BEC5 45%, #8a9aa5 55%, #B0BEC5 70%, #CFD8DC 85%, #7a8590 100%)',
    border: 'rgba(207,216,220,0.4)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.3), inset 0 -1px 0 rgba(0,0,0,0.3), 0 2px 4px rgba(0,0,0,0.5), 0 1px 0 rgba(176,190,197,0.15)',
    text: '#1a1e22',
    highlight: 'rgba(207,216,220,0.5)',
  },
  gunmetal: {
    gradient: 'linear-gradient(145deg, #3a3e44 0%, #4d5259 12%, #626870 25%, #6e747c 35%, #5a6068 45%, #4d5259 55%, #626870 68%, #6e747c 78%, #5a6068 88%, #3a3e44 100%)',
    border: 'rgba(110,116,124,0.5)',
    shadow: 'inset 0 1px 0 rgba(255,255,255,0.2), inset 0 -1px 0 rgba(0,0,0,0.35), 0 2px 6px rgba(0,0,0,0.5), 0 1px 0 rgba(90,96,104,0.2)',
    text: '#111214',
    highlight: 'rgba(160,166,174,0.35)',
  },
};

// Map service_id + tier to metal
const TIER_METAL: Record<string, Record<string, string>> = {
  goals: { standard: 'rose', premium: 'titanium', citizen: 'gunmetal' },
  aca: { standard: 'rose', enthusiast: 'titanium', padawan: 'gunmetal' },
};

export default function Dashboard() {
  const { user, session } = useAuth();
  const navigate = useNavigate();
  const [profile, setProfile] = useState<ProfileSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [plaidLoading, setPlaidLoading] = useState(false);
  const [pullLoadingId, setPullLoadingId] = useState<string | null>(null);
  const [pullResult, setPullResult] = useState<string | null>(null);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState<string | null>(null);
  const [gameCards, setGameCards] = useState<any[] | null>(null);
  const [shredLoading, setShredLoading] = useState(false);
  const [shredResult, setShredResult] = useState<string | null>(null);
  const [lastAttestation, setLastAttestation] = useState<string | null>(null);
  const [removeLoadingId, setRemoveLoadingId] = useState<string | null>(null);

  useEffect(() => {
    if (session?.access_token) {
      fetchProfile();
    }
  }, [session]);

  const fetchProfile = async () => {
    // Always get the latest token — session in closure may be stale
    const { data: { session: current } } = await supabase.auth.getSession();
    const token = current?.access_token;
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
            const exchangeRes = await fetch(
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
            if (!exchangeRes.ok) {
              throw new Error('Exchange failed: ' + exchangeRes.status);
            }
            await fetchProfile();
          } catch (err) {
            console.error('Token exchange failed:', err);
            setError('Failed to connect account. Please try again.');
          } finally {
            setPlaidLoading(false);
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

  const pullTransactions = async (accountId: string) => {
    const token = await getFreshToken();
    if (!token) return;

    setPullLoadingId(accountId);
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
          body: JSON.stringify({ account_id: accountId }),
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
      setPullLoadingId(null);
    }
  };

  const removeCard = async (accountId: string) => {
    if (!confirm('Disconnect this card?')) return;

    const token = await getFreshToken();
    if (!token) return;

    setRemoveLoadingId(accountId);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/remove-card`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
          body: JSON.stringify({ account_id: accountId }),
        }
      );
      if (!res.ok) throw new Error('Failed to remove card');
      await fetchProfile();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRemoveLoadingId(null);
    }
  };

  const shredAndSend = async () => {
    if (!lastAttestation) return;

    const token = await getFreshToken();
    if (!token) return;

    setShredLoading(true);
    setShredResult(null);
    try {
      // Shred raw transactions
      const shredRes = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/shred-minted-transactions`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'apikey': import.meta.env.ZULE_PUBLISHABLE_KEY,
          },
        }
      );

      const shredData = shredRes.ok ? await shredRes.json() : null;

      // Cards handed off — clear from Zule's state
      setShredResult(`Shredded ${shredData?.shredded || 0} raw transactions. Cards dispatched.`);
      setGameCards(null);
      setLastAttestation(null);
      setAnalyzeResult(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setShredLoading(false);
    }
  };

  const analyzeAndSend = async () => {
    const token = await getFreshToken();
    if (!token) return;

    setAnalyzeLoading(true);
    setAnalyzeResult(null);
    try {
      const res = await fetch(
        `${import.meta.env.ZULE_URL}/functions/v1/mint-transaction-cards`,
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
        throw new Error(err.error || 'Failed to analyze transactions');
      }

      const data = await res.json();

      if (!data.card_attestation || data.card_count === 0) {
        setAnalyzeResult('No new transactions to analyze');
        return;
      }

      // Decode JWT payload to display game event cards
      try {
        const parts = data.card_attestation.split('.');
        let padded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        while (padded.length % 4 !== 0) padded += '=';
        const payload = JSON.parse(atob(padded));
        setGameCards(payload.cards || []);
        setLastAttestation(data.card_attestation);
      } catch {
        setGameCards(null);
        setLastAttestation(null);
      }

      setAnalyzeResult(`Minted ${data.card_count} game event cards`);
      setShredResult(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnalyzeLoading(false);
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

      {error && <div className="error-message">{error}</div>}

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

        {/* Subscriptions */}
        <div className="card">
          <h2>Subscriptions</h2>
          {profile?.subscriptions && profile.subscriptions.filter(s => s.status === 'active').length > 0 ? (
            profile.subscriptions.filter(s => s.status === 'active').map((sub) => {
              const m = metals[TIER_METAL[sub.service_id]?.[sub.tier] || 'rose'] || metals.rose;
              return (
                <div className="info-row" key={sub.service_id}>
                  <span className="label">{SERVICE_DISPLAY_NAME[sub.service_id] || sub.service_id}</span>
                  <span className="value">
                    <div className="metal-btn" onClick={() => navigate(`/subscriptions?service=${sub.service_id}`)} style={{
                      cursor: 'pointer', display: 'inline-block', minWidth: '120px', textAlign: 'center',
                      padding: '8px 12px', borderRadius: '4px',
                      fontFamily: "'Cormorant Garamond', serif", fontWeight: 600, fontSize: '12px',
                      letterSpacing: '0.14em', textTransform: 'uppercase',
                      background: m.gradient, backgroundSize: '200% auto',
                      color: m.text, boxShadow: m.shadow,
                      borderTop: `1px solid ${m.border}`,
                      borderBottom: '1px solid rgba(0,0,0,0.4)',
                      textShadow: `0 1px 0 ${m.highlight}`,
                      position: 'relative', overflow: 'hidden',
                    }}>
                      <span style={{ position: 'relative', zIndex: 1 }}>{sub.tier}</span>
                      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '50%', background: 'linear-gradient(180deg, rgba(255,255,255,0.12) 0%, transparent 100%)', pointerEvents: 'none' }} />
                    </div>
                  </span>
                </div>
              );
            })
          ) : (
            <div className="info-row">
              <span className="label">Goals</span>
              <span className="value">
                <div className="metal-btn" onClick={() => navigate('/subscriptions?service=goals')} style={{
                  cursor: 'pointer', display: 'inline-block', minWidth: '120px', textAlign: 'center',
                  padding: '8px 12px', borderRadius: '4px',
                  fontFamily: "'Cormorant Garamond', serif", fontWeight: 600, fontSize: '12px',
                  letterSpacing: '0.14em', textTransform: 'uppercase',
                  background: metals.gunmetal.gradient, backgroundSize: '200% auto',
                  color: metals.gunmetal.text, boxShadow: metals.gunmetal.shadow,
                  borderTop: `1px solid ${metals.gunmetal.border}`,
                  borderBottom: '1px solid rgba(0,0,0,0.4)',
                  textShadow: `0 1px 0 ${metals.gunmetal.highlight}`,
                  position: 'relative', overflow: 'hidden',
                }}>
                  <span style={{ position: 'relative', zIndex: 1 }}>citizen</span>
                  <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '50%', background: 'linear-gradient(180deg, rgba(255,255,255,0.12) 0%, transparent 100%)', pointerEvents: 'none' }} />
                </div>
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Connected Accounts (Plaid) */}
      <div className="card">
        <h2>Connected Accounts</h2>
        {profile?.plaid_accounts && profile.plaid_accounts.length > 0 ? (
          <>
            {profile.plaid_accounts.map((acct) => (
              <div key={acct.id} style={{ marginBottom: '12px', padding: '8px', border: '1px solid #222', borderRadius: '4px' }}>
                <div className="info-row" style={{ marginBottom: '4px' }}>
                  <span className="label">{acct.institution_name}</span>
                  <span className="value" style={{ fontSize: '11px', opacity: 0.5 }}>{formatDate(acct.connected_at)}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                  <button
                    className="btn-secondary"
                    onClick={() => pullTransactions(acct.id)}
                    disabled={pullLoadingId === acct.id}
                    style={{ fontSize: '11px', padding: '4px 10px' }}
                  >
                    {pullLoadingId === acct.id ? 'Pulling...' : 'Pull'}
                  </button>
                  <button
                    onClick={() => removeCard(acct.id)}
                    disabled={removeLoadingId === acct.id}
                    style={{ fontSize: '10px', color: '#ef4444', background: 'none', border: '1px solid #ef4444', padding: '3px 8px', borderRadius: '3px', cursor: 'pointer' }}
                  >
                    {removeLoadingId === acct.id ? '...' : 'Remove'}
                  </button>
                </div>
                {pullResult && (
                  <div className="success-message" style={{ marginTop: '6px', fontSize: '11px' }}>
                    {pullResult}
                  </div>
                )}
              </div>
            ))}
            <div style={{ marginTop: '16px' }}>
              <button
                className="btn-primary"
                onClick={analyzeAndSend}
                disabled={analyzeLoading}
                style={{ marginTop: '8px' }}
              >
                {analyzeLoading ? 'Analyzing...' : 'Analyze & Mint Cards'}
              </button>
              {analyzeResult && (
                <div className="success-message" style={{ marginTop: '12px' }}>
                  {analyzeResult}
                </div>
              )}
              {gameCards && gameCards.length > 0 && (
                <button
                  className="btn-primary"
                  onClick={shredAndSend}
                  disabled={shredLoading}
                  style={{ marginTop: '8px' }}
                >
                  {shredLoading ? 'Shredding...' : 'Shred & Send'}
                </button>
              )}
              {shredResult && (
                <div className="success-message" style={{ marginTop: '12px' }}>
                  {shredResult}
                </div>
              )}
            </div>
            {gameCards && gameCards.length > 0 && (
              <div style={{ marginTop: '16px' }}>
                <h3 style={{ fontSize: '12px', fontFamily: 'monospace', textTransform: 'uppercase', opacity: 0.5, marginBottom: '8px', letterSpacing: '0.1em' }}>
                  Game Event Cards — This is what crosses the privacy boundary
                </h3>
                {gameCards.map((card: any, i: number) => (
                  <div key={i} style={{
                    border: '1px solid #333', borderRadius: '6px', padding: '12px',
                    marginBottom: '8px', fontSize: '12px', fontFamily: 'monospace',
                    background: '#0a0a0a',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ color: '#fff', fontWeight: 'bold' }}>
                        {card.merchant || 'Unknown'}
                      </span>
                      <span style={{ color: '#f59e0b' }}>
                        {(card.xp_awards?.purchase_xp || 0) + (card.xp_awards?.sponsor_xp || 0) + (card.xp_awards?.quest_xp || 0)} XP
                      </span>
                    </div>
                    {card.description && (
                      <div style={{ color: '#aaa', fontSize: '11px', marginBottom: '4px' }}>
                        {card.description}
                      </div>
                    )}
                    {card.category && (
                      <div style={{ color: '#666', fontSize: '10px', marginBottom: '4px' }}>
                        {card.category}
                      </div>
                    )}
                    <div style={{ color: '#666', fontSize: '10px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {card.xp_awards?.sponsor_xp > 0 && <span style={{ color: '#10b981' }}>sponsor:{card.xp_awards.sponsor_xp}</span>}
                      {card.xp_awards?.quest_xp > 0 && <span style={{ color: '#a855f7' }}>quest:{card.xp_awards.quest_xp}</span>}
                      {card.pool_hits?.length > 0 && <span style={{ color: '#10b981' }}>pools:{card.pool_hits.join(',')}</span>}
                      {card.quest_template_hits?.length > 0 && <span style={{ color: '#a855f7' }}>quests:{card.quest_template_hits.join(',')}</span>}
                      {card.activity_tag && <span style={{ color: '#06b6d4' }}>{card.activity_tag}</span>}
                      {card.location_verified && <span style={{ color: '#22c55e' }}>LOC</span>}
                      <span style={{ color: '#444' }}>tick:{card.cosmic_tick}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <div className="info-note" style={{ marginTop: '12px' }}>
              <p>Pull transactions from Plaid, then analyze to see the enriched game event cards. Only game data reaches Goals — no financial details.</p>
            </div>
          </>
        ) : (
          <div className="info-note">
            <p>Link your accounts for automated challenge verification and other features. See our <a href="/privacy" style={{ color: 'var(--zule-gold)', textDecoration: 'none' }}>privacy policy</a> and <a href="/terms" style={{ color: 'var(--zule-gold)', textDecoration: 'none' }}>terms</a> for full details.</p>
          </div>
        )}
        <div style={{ marginTop: '16px' }}>
          <button
            className="btn-primary"
            onClick={openPlaidLink}
            disabled={plaidLoading}
          >
            {plaidLoading ? 'Connecting...' : 'Link Card'}
          </button>
        </div>
      </div>

      {/* Vinzrik Notice */}
      <div className="card">
        <h2>App Connections</h2>
        <div className="info-note">
          <p>
            Connect your daily use apps here. Don't see an app you use? Let us know and we'll see what we can do.
          </p>
        </div>
      </div>
    </div>
  );
}
