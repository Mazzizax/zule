import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { useAuth } from '../../src/contexts/AuthContext';
import { useRouter } from 'expo-router';

/**
 * Dashboard Screen
 *
 * Account overview, subscription status, last active
 */
export default function DashboardScreen() {
  const { user, signOut } = useAuth();
  const router = useRouter();

  const handleSignOut = async () => {
    await signOut();
    router.replace('/login');
  };

  const memberSince = user?.created_at
    ? new Date(user.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      })
    : 'Unknown';

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Account Overview</Text>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Email</Text>
          <Text style={styles.value}>{user?.email || 'Unknown'}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Member Since</Text>
          <Text style={styles.value}>{memberSince}</Text>
        </View>

        <View style={styles.infoRow}>
          <Text style={styles.label}>Subscription</Text>
          <View style={styles.badge}>
            <Text style={styles.badgeText}>Free</Text>
          </View>
        </View>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Privacy Status</Text>
        <Text style={styles.description}>
          Gatekeeper knows your identity to manage your account.
          Apps you connect to through Dawg Tag only see your ghost_id - never your email or user ID.
        </Text>
        <View style={styles.statusRow}>
          <View style={styles.statusDot} />
          <Text style={styles.statusText}>Identity Protected</Text>
        </View>
      </View>

      <TouchableOpacity style={styles.signOutButton} onPress={handleSignOut}>
        <Text style={styles.signOutText}>Sign Out</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    padding: 16,
  },
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
  label: {
    fontSize: 14,
    color: '#888',
  },
  value: {
    fontSize: 14,
    color: '#fff',
  },
  badge: {
    backgroundColor: '#4CAF50',
    paddingHorizontal: 12,
    paddingVertical: 4,
    borderRadius: 12,
  },
  badgeText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '600',
  },
  description: {
    fontSize: 14,
    color: '#888',
    lineHeight: 20,
    marginBottom: 16,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#4CAF50',
    marginRight: 8,
  },
  statusText: {
    fontSize: 14,
    color: '#4CAF50',
    fontWeight: '600',
  },
  signOutButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#f44336',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 'auto',
  },
  signOutText: {
    color: '#f44336',
    fontSize: 16,
    fontWeight: '600',
  },
});
