import { useEffect, useState, useCallback } from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ActivityIndicator, ScrollView, Alert } from 'react-native';
import { useAuth } from '../../src/contexts/AuthContext';
import { useRouter } from 'expo-router';
import { create, open, dismissLink } from 'react-native-plaid-link-sdk';
import { supabase } from '../../src/lib/supabase';

/**
 * Dashboard Screen
 *
 * Account overview, subscription status, connected financial accounts (Plaid),
 * transaction pipeline (pull → analyze/mint → shred).
 */

interface PlaidAccount {
  id: string;
  institution_name: string;
  connected_at: string;
  status?: string;
}

interface Subscription {
  service_id: string;
  tier: string;
  status: string;
}

interface ProfileSummary {
  subscription_tier: string;
  created_at: string;
  last_seen_at: string;
  plaid_accounts: PlaidAccount[];
  subscriptions: Subscription[];
}

const SERVICE_DISPLAY_NAME: Record<string, string> = {
  goals: 'Goals',
  aca: 'Advanced Cognitive Assistant',
};

async function getFreshToken(): Promise<string | null> {
  const { data: { session } } = await supabase.auth.getSession();
  return session?.access_token ?? null;
}

const ZULE_URL = process.env.EXPO_PUBLIC_ZULE_URL || '';
const ZULE_KEY = process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY || '';

export default function DashboardScreen() {
  const { user, session, loading, signOut } = useAuth();
  const router = useRouter();
  const [profile, setProfile] = useState<ProfileSummary | null>(null);
  const [profileLoading, setProfileLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [plaidLoading, setPlaidLoading] = useState(false);
  const [pullLoadingId, setPullLoadingId] = useState<string | null>(null);
  const [pullResult, setPullResult] = useState<string | null>(null);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState<string | null>(null);
  const [shredLoading, setShredLoading] = useState(false);
  const [shredResult, setShredResult] = useState<string | null>(null);
  const [lastAttestation, setLastAttestation] = useState<string | null>(null);
  const [removeLoadingId, setRemoveLoadingId] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && !session) {
      router.replace('/login');
    }
  }, [loading, session]);

  useEffect(() => {
    if (session) fetchProfile();
  }, [session]);

  const fetchProfile = async () => {
    const token = await getFreshToken();
    if (!token) { setProfileLoading(false); return; }

    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/user-profile`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
      });
      if (!res.ok) throw new Error('Failed to fetch profile');
      setProfile(await res.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setProfileLoading(false);
    }
  };

  const openPlaidLink = useCallback(async () => {
    const token = await getFreshToken();
    if (!token) return;

    setPlaidLoading(true);
    setError(null);
    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/plaid-create-link-token`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to create link token');
      }

      const { link_token } = await res.json();

      create({ token: link_token });
      open({
        onSuccess: async ({ publicToken }) => {
          try {
            const exchangeToken = await getFreshToken();
            const exchangeRes = await fetch(`${ZULE_URL}/functions/v1/plaid-exchange-token`, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${exchangeToken}`,
                'Content-Type': 'application/json',
                'apikey': ZULE_KEY,
              },
              body: JSON.stringify({ public_token: publicToken }),
            });
            if (!exchangeRes.ok) throw new Error('Exchange failed');
            await fetchProfile();
          } catch (err: any) {
            setError('Failed to connect account. Please try again.');
          } finally {
            setPlaidLoading(false);
          }
        },
        onExit: () => {
          setPlaidLoading(false);
        },
      });
    } catch (err: any) {
      setError(err.message);
      setPlaidLoading(false);
    }
  }, []);

  const UPDATE_STATUSES = ['login_required', 'pending_expiration', 'pending_disconnect'];

  const openPlaidUpdate = useCallback(async (accountId: string) => {
    const token = await getFreshToken();
    if (!token) return;

    setPlaidLoading(true);
    setError(null);
    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/plaid-update-link-token`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
        body: JSON.stringify({ account_id: accountId }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to create update link token');
      }

      const { link_token } = await res.json();

      create({ token: link_token });
      open({
        onSuccess: async () => {
          // No token exchange needed in update mode
          await fetchProfile();
          setPlaidLoading(false);
        },
        onExit: () => {
          setPlaidLoading(false);
        },
      });
    } catch (err: any) {
      setError(err.message);
      setPlaidLoading(false);
    }
  }, []);

  const pullTransactions = async (accountId: string) => {
    const token = await getFreshToken();
    if (!token) return;

    setPullLoadingId(accountId);
    setPullResult(null);
    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/plaid-pull-transactions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
        body: JSON.stringify({ account_id: accountId }),
      });
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
    Alert.alert('Disconnect Card', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Disconnect', style: 'destructive', onPress: async () => {
          const token = await getFreshToken();
          if (!token) return;
          setRemoveLoadingId(accountId);
          try {
            const res = await fetch(`${ZULE_URL}/functions/v1/remove-card`, {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                'apikey': ZULE_KEY,
              },
              body: JSON.stringify({ account_id: accountId }),
            });
            if (!res.ok) throw new Error('Failed to remove card');
            await fetchProfile();
          } catch (err: any) {
            setError(err.message);
          } finally {
            setRemoveLoadingId(null);
          }
        },
      },
    ]);
  };

  const analyzeAndMint = async () => {
    const token = await getFreshToken();
    if (!token) return;

    setAnalyzeLoading(true);
    setAnalyzeResult(null);
    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/mint-transaction-cards`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to analyze transactions');
      }
      const data = await res.json();
      if (!data.card_attestation || data.card_count === 0) {
        setAnalyzeResult('No new transactions to analyze');
        return;
      }
      setLastAttestation(data.card_attestation);
      setAnalyzeResult(`Minted ${data.card_count} game event cards`);
      setShredResult(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnalyzeLoading(false);
    }
  };

  const shredAndSend = async () => {
    if (!lastAttestation) return;
    const token = await getFreshToken();
    if (!token) return;

    setShredLoading(true);
    setShredResult(null);
    try {
      const res = await fetch(`${ZULE_URL}/functions/v1/shred-minted-transactions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'apikey': ZULE_KEY,
        },
      });
      const data = res.ok ? await res.json() : null;
      setShredResult(`Shredded ${data?.shredded || 0} raw transactions. Cards dispatched.`);
      setLastAttestation(null);
      setAnalyzeResult(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setShredLoading(false);
    }
  };

  const handleSignOut = async () => {
    await signOut();
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric',
    });
  };

  if (loading || profileLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#4CAF50" />
      </View>
    );
  }

  const activeAccounts = profile?.plaid_accounts || [];
  const activeSubs = profile?.subscriptions?.filter(s => s.status === 'active') || [];

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {error && (
        <View style={styles.errorBanner}>
          <Text style={styles.errorText}>{error}</Text>
          <TouchableOpacity onPress={() => setError(null)}>
            <Text style={styles.dismissText}>✕</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Account Info */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Account</Text>
        <View style={styles.infoRow}>
          <Text style={styles.label}>Email</Text>
          <Text style={styles.value}>{user?.email || 'Unknown'}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.label}>Member Since</Text>
          <Text style={styles.value}>{formatDate(profile?.created_at || user?.created_at || null)}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.label}>Last Active</Text>
          <Text style={styles.value}>{formatDate(profile?.last_seen_at || null)}</Text>
        </View>
      </View>

      {/* Subscriptions */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Subscriptions</Text>
        {activeSubs.length > 0 ? (
          activeSubs.map(sub => (
            <View style={styles.infoRow} key={sub.service_id}>
              <Text style={styles.label}>{SERVICE_DISPLAY_NAME[sub.service_id] || sub.service_id}</Text>
              <View style={styles.badge}>
                <Text style={styles.badgeText}>{sub.tier}</Text>
              </View>
            </View>
          ))
        ) : (
          <View style={styles.infoRow}>
            <Text style={styles.label}>Goals</Text>
            <View style={styles.badge}>
              <Text style={styles.badgeText}>citizen</Text>
            </View>
          </View>
        )}
      </View>

      {/* Connected Accounts (Plaid) */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Connected Accounts</Text>

        {activeAccounts.length > 0 ? (
          <>
            {activeAccounts.map(acct => (
              <View key={acct.id} style={styles.accountCard}>
                <View style={styles.accountHeader}>
                  <Text style={styles.institutionName}>{acct.institution_name}</Text>
                  <Text style={styles.connectedDate}>{formatDate(acct.connected_at)}</Text>
                </View>
                {acct.status === 'new_accounts_available' && (
                  <Text style={styles.statusNote}>New accounts available at this institution</Text>
                )}
                {acct.status && UPDATE_STATUSES.includes(acct.status) && (
                  <View style={styles.updateBanner}>
                    <Text style={styles.updateText}>
                      {acct.status === 'login_required' ? 'Login required — re-authenticate to continue' :
                       acct.status === 'pending_expiration' ? 'Access expiring — re-authenticate to renew' :
                       'Pending disconnect — re-authenticate to maintain access'}
                    </Text>
                    <TouchableOpacity
                      style={styles.btnUpdate}
                      onPress={() => openPlaidUpdate(acct.id)}
                      disabled={plaidLoading}
                    >
                      <Text style={styles.btnUpdateText}>Update</Text>
                    </TouchableOpacity>
                  </View>
                )}
                <View style={styles.accountActions}>
                  <TouchableOpacity
                    style={styles.btnSecondary}
                    onPress={() => pullTransactions(acct.id)}
                    disabled={pullLoadingId === acct.id}
                  >
                    <Text style={styles.btnSecondaryText}>
                      {pullLoadingId === acct.id ? 'Pulling...' : 'Pull'}
                    </Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={styles.btnDanger}
                    onPress={() => removeCard(acct.id)}
                    disabled={removeLoadingId === acct.id}
                  >
                    <Text style={styles.btnDangerText}>
                      {removeLoadingId === acct.id ? '...' : 'Remove'}
                    </Text>
                  </TouchableOpacity>
                </View>
                {pullResult && pullLoadingId === null && (
                  <Text style={styles.successText}>{pullResult}</Text>
                )}
              </View>
            ))}

            {/* Analyze & Mint */}
            <TouchableOpacity
              style={styles.btnPrimary}
              onPress={analyzeAndMint}
              disabled={analyzeLoading}
            >
              <Text style={styles.btnPrimaryText}>
                {analyzeLoading ? 'Analyzing...' : 'Analyze & Mint Cards'}
              </Text>
            </TouchableOpacity>
            {analyzeResult && <Text style={styles.successText}>{analyzeResult}</Text>}

            {/* Shred & Send */}
            {lastAttestation && (
              <TouchableOpacity
                style={[styles.btnPrimary, { marginTop: 8 }]}
                onPress={shredAndSend}
                disabled={shredLoading}
              >
                <Text style={styles.btnPrimaryText}>
                  {shredLoading ? 'Shredding...' : 'Shred & Send'}
                </Text>
              </TouchableOpacity>
            )}
            {shredResult && <Text style={styles.successText}>{shredResult}</Text>}

            <Text style={styles.noteText}>
              Pull transactions from Plaid, then analyze to see enriched game event cards. Only game data reaches Goals — no financial details.
            </Text>
          </>
        ) : (
          <Text style={styles.noteText}>
            Link your accounts for automated challenge verification and other features.
          </Text>
        )}

        <TouchableOpacity
          style={[styles.btnPrimary, { marginTop: 16 }]}
          onPress={openPlaidLink}
          disabled={plaidLoading}
        >
          <Text style={styles.btnPrimaryText}>
            {plaidLoading ? 'Connecting...' : 'Link Card'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Privacy Status */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Privacy Status</Text>
        <Text style={styles.description}>
          Zule knows your identity to manage your account.
          Apps you connect to through Vinzrik only see your ghost_id - never your email or user ID.
        </Text>
        <View style={styles.statusRow}>
          <View style={styles.statusDot} />
          <Text style={styles.statusText}>Identity Protected</Text>
        </View>
      </View>

      <TouchableOpacity style={styles.signOutButton} onPress={handleSignOut}>
        <Text style={styles.signOutText}>Sign Out</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
  },
  content: {
    padding: 16,
    paddingBottom: 32,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a2e',
  },
  errorBanner: {
    backgroundColor: '#f4433620',
    borderWidth: 1,
    borderColor: '#f44336',
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  errorText: { color: '#f44336', fontSize: 13, flex: 1 },
  dismissText: { color: '#f44336', fontSize: 16, paddingLeft: 12 },
  card: {
    backgroundColor: '#252542',
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 16,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#333',
  },
  label: { fontSize: 14, color: '#888' },
  value: { fontSize: 14, color: '#fff' },
  badge: {
    backgroundColor: '#4CAF50',
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 12,
  },
  badgeText: { color: '#fff', fontSize: 12, fontWeight: '600' },
  accountCard: {
    borderWidth: 1,
    borderColor: '#333',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
  },
  accountHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  institutionName: { color: '#fff', fontSize: 14, fontWeight: '600' },
  connectedDate: { color: '#666', fontSize: 11 },
  statusNote: { color: '#f59e0b', fontSize: 12, marginBottom: 8 },
  updateBanner: {
    backgroundColor: '#f59e0b20',
    borderWidth: 1,
    borderColor: '#f59e0b40',
    borderRadius: 6,
    padding: 10,
    marginBottom: 8,
  },
  updateText: { color: '#f59e0b', fontSize: 12, marginBottom: 6 },
  btnUpdate: {
    borderWidth: 1,
    borderColor: '#f59e0b',
    borderRadius: 6,
    paddingVertical: 5,
    paddingHorizontal: 14,
    alignSelf: 'flex-start',
  },
  btnUpdateText: { color: '#f59e0b', fontSize: 12, fontWeight: '600' },
  accountActions: {
    flexDirection: 'row',
    gap: 8,
  },
  btnPrimary: {
    backgroundColor: '#4CAF50',
    borderRadius: 8,
    padding: 14,
    alignItems: 'center',
    marginTop: 12,
  },
  btnPrimaryText: { color: '#fff', fontSize: 14, fontWeight: '600' },
  btnSecondary: {
    borderWidth: 1,
    borderColor: '#4CAF50',
    borderRadius: 6,
    paddingVertical: 6,
    paddingHorizontal: 14,
  },
  btnSecondaryText: { color: '#4CAF50', fontSize: 12 },
  btnDanger: {
    borderWidth: 1,
    borderColor: '#f44336',
    borderRadius: 6,
    paddingVertical: 6,
    paddingHorizontal: 14,
  },
  btnDangerText: { color: '#f44336', fontSize: 12 },
  successText: { color: '#4CAF50', fontSize: 12, marginTop: 8 },
  noteText: { color: '#888', fontSize: 13, lineHeight: 18, marginTop: 12 },
  description: {
    fontSize: 14,
    color: '#888',
    lineHeight: 20,
    marginBottom: 16,
  },
  statusRow: { flexDirection: 'row', alignItems: 'center' },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#4CAF50',
    marginRight: 8,
  },
  statusText: { fontSize: 14, color: '#4CAF50', fontWeight: '600' },
  signOutButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#f44336',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 8,
  },
  signOutText: { color: '#f44336', fontSize: 16, fontWeight: '600' },
});
