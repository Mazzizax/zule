import { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Alert,
  ScrollView,
} from 'react-native';
import { useAuth } from '../../src/contexts/AuthContext';
import { supabase } from '../../src/lib/supabase';

/**
 * Profile Screen
 *
 * Edit display name, timezone, view subscription tier
 */

interface UserProfile {
  display_name: string | null;
  timezone: string | null;
  subscription_tier: string;
}

export default function ProfileScreen() {
  const { user } = useAuth();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    loadProfile();
  }, [user]);

  const loadProfile = async () => {
    if (!user) return;

    try {
      const { data, error } = await supabase
        .from('user_profiles')
        .select('display_name, timezone, subscription_tier')
        .eq('id', user.id)
        .single();

      if (error && error.code !== 'PGRST116') {
        throw error;
      }

      if (data) {
        setProfile(data);
        setDisplayName(data.display_name || '');
      }
    } catch (err: any) {
      console.error('Failed to load profile:', err.message);
    } finally {
      setLoading(false);
    }
  };

  const saveProfile = async () => {
    if (!user) return;

    setSaving(true);
    try {
      const { error } = await supabase
        .from('user_profiles')
        .upsert({
          id: user.id,
          display_name: displayName || null,
          updated_at: new Date().toISOString(),
        });

      if (error) throw error;

      Alert.alert('Success', 'Profile updated successfully');
      loadProfile();
    } catch (err: any) {
      Alert.alert('Error', err.message || 'Failed to save profile');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#4CAF50" />
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Profile Information</Text>

        <View style={styles.field}>
          <Text style={styles.label}>Email</Text>
          <Text style={styles.valueText}>{user?.email || 'Unknown'}</Text>
          <Text style={styles.hint}>Email cannot be changed</Text>
        </View>

        <View style={styles.field}>
          <Text style={styles.label}>Display Name</Text>
          <TextInput
            style={styles.input}
            value={displayName}
            onChangeText={setDisplayName}
            placeholder="Enter display name"
            placeholderTextColor="#666"
            editable={!saving}
          />
        </View>

        <TouchableOpacity
          style={[styles.saveButton, saving && styles.buttonDisabled]}
          onPress={saveProfile}
          disabled={saving}
        >
          {saving ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.saveButtonText}>Save Changes</Text>
          )}
        </TouchableOpacity>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Subscription</Text>

        <View style={styles.tierRow}>
          <View style={styles.tierBadge}>
            <Text style={styles.tierText}>
              {profile?.subscription_tier || 'free'}
            </Text>
          </View>
          <Text style={styles.tierDescription}>
            {profile?.subscription_tier === 'free'
              ? 'Basic access to all features'
              : 'Premium features enabled'}
          </Text>
        </View>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    padding: 16,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a2e',
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
    marginBottom: 20,
  },
  field: {
    marginBottom: 20,
  },
  label: {
    fontSize: 14,
    color: '#888',
    marginBottom: 8,
  },
  valueText: {
    fontSize: 16,
    color: '#fff',
  },
  hint: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  input: {
    backgroundColor: '#1a1a2e',
    borderRadius: 8,
    padding: 12,
    color: '#fff',
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#333',
  },
  saveButton: {
    backgroundColor: '#4CAF50',
    borderRadius: 8,
    padding: 16,
    alignItems: 'center',
    marginTop: 8,
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  saveButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  tierRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  tierBadge: {
    backgroundColor: '#4CAF50',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 12,
    marginRight: 12,
  },
  tierText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  tierDescription: {
    flex: 1,
    fontSize: 14,
    color: '#888',
  },
});
