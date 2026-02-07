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
  Linking,
} from 'react-native';
import { useAuth } from '../../src/contexts/AuthContext';
import { supabase } from '../../src/lib/supabase';
import { registerPasskey, clearStoredPasskey, hasStoredPasskey } from '../../src/lib/passkey';

interface PasskeyInfo {
  id: string;
  device_name: string;
  created_at: string;
}

export default function SecurityScreen() {
  console.log('[SECURITY] ====== SECURITY SCREEN LOADED - PAIRING CODE PRESENT ======');
  const { user } = useAuth();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);
  
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [linkingDevice, setLinkingDevice] = useState(false);
  const [clearingPasskey, setClearingPasskey] = useState(false);
  const [hasLocalPasskey, setHasLocalPasskey] = useState(false);
  const [pairingDawgTag, setPairingDawgTag] = useState(false);

  useEffect(() => {
    loadPasskeys();
    checkLocalPasskey();
  }, []);

  const checkLocalPasskey = async () => {
    const stored = await hasStoredPasskey();
    setHasLocalPasskey(stored);
  };

  const loadPasskeys = async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession();

      if (!session?.access_token) {
        console.warn('[Security] No active session');
        setLoadingKeys(false);
        return;
      }

      console.log('[Security] Calling passkey-register with token:', session.access_token.substring(0, 20) + '...');

      // Use direct fetch since supabase.functions.invoke doesn't pass Authorization header correctly
      const functionUrl = `${process.env.EXPO_PUBLIC_ZULE_URL}/functions/v1/passkey-register`;
      const fetchResponse = await fetch(functionUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'apikey': process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY || '',
          'Content-Type': 'application/json',
        },
      });

      const response = {
        data: fetchResponse.ok ? await fetchResponse.json() : null,
        error: fetchResponse.ok ? null : new Error(`HTTP ${fetchResponse.status}`),
      };
      
      if (response.error) {
        console.warn('[Security] Function returned error:', response.error);
        console.warn('[Security] Error context:', JSON.stringify(response.error, null, 2));
        console.warn('[Security] Response data:', response.data);
        setPasskeys([]);
      } else {
        setPasskeys(response.data?.passkeys || []);
      }
    } catch (err: any) {
      console.error('[Security] Fetch Exception:', err.message);
    } finally {
      setLoadingKeys(false);
    }
  };

  const handleLinkDevice = async () => {
    setLinkingDevice(true);
    try {
      const result = await registerPasskey(user?.email || '');
      if (result.success) {
        Alert.alert('Success', 'Device linked.');
        loadPasskeys();
      } else {
        Alert.alert('Registration Error', result.error);
      }
    } catch (err: any) {
      Alert.alert('Error', 'Hardware communication failed.');
    } finally {
      setLinkingDevice(false);
    }
  };

  const handleClearPasskey = async () => {
    Alert.alert(
      'Clear Passkey',
      'This will remove the passkey from this device. You will need to re-register to use biometric login.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
          style: 'destructive',
          onPress: async () => {
            setClearingPasskey(true);
            try {
              await clearStoredPasskey();
              setHasLocalPasskey(false);
              Alert.alert('Success', 'Passkey cleared from device.');
            } catch (err: any) {
              Alert.alert('Error', err.message);
            } finally {
              setClearingPasskey(false);
            }
          },
        },
      ]
    );
  };

  const handleDeletePasskey = async (passkeyId: string, deviceName: string) => {
    Alert.alert(
      'Delete Passkey',
      `Remove "${deviceName}" from your account?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              const { data: { session } } = await supabase.auth.getSession();
              if (!session?.access_token) {
                Alert.alert('Error', 'No active session');
                return;
              }

              const functionUrl = `${process.env.EXPO_PUBLIC_ZULE_URL}/functions/v1/passkey-register`;
              const response = await fetch(functionUrl, {
                method: 'DELETE',
                headers: {
                  'Authorization': `Bearer ${session.access_token}`,
                  'apikey': process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY || '',
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({ passkey_id: passkeyId }),
              });

              if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText);
              }

              Alert.alert('Success', 'Passkey deleted.');
              loadPasskeys();
            } catch (err: any) {
              Alert.alert('Error', err.message);
            }
          },
        },
      ]
    );
  };

  const handleChangePassword = async () => {
    if (newPassword !== confirmPassword) {
      Alert.alert('Error', 'Passwords mismatch');
      return;
    }
    setChangingPassword(true);
    try {
      const { error } = await supabase.auth.updateUser({ password: newPassword });
      if (error) throw error;
      Alert.alert('Success', 'Password updated');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      Alert.alert('Error', err.message);
    } finally {
      setChangingPassword(false);
    }
  };

  const handlePairDawgTag = async () => {
    console.log('[SECURITY] ====== PAIR VINZRIK PRESSED ======');
    setPairingDawgTag(true);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      console.log('[SECURITY] Session exists:', !!session?.access_token);

      if (!session?.access_token) {
        Alert.alert('Error', 'Please sign in first');
        return;
      }

      // Create pairing challenge
      const functionUrl = `${process.env.EXPO_PUBLIC_ZULE_URL}/functions/v1/pair-client`;
      console.log('[SECURITY] Calling:', functionUrl);
      console.log('[SECURITY] Has apikey:', !!process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY);
      const response = await fetch(functionUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${session.access_token}`,
          'apikey': process.env.EXPO_PUBLIC_ZULE_PUBLISHABLE_KEY || '',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'create_challenge',
          client_app_id: 'vinzrik',
          client_app_name: 'Vinzrik',
        }),
      });

      console.log('[SECURITY] Response status:', response.status);
      if (!response.ok) {
        const errorText = await response.text();
        console.error('[SECURITY] Error response:', errorText);
        throw new Error(errorText);
      }

      const { challenge } = await response.json();

      // Open Vinzrik with pairing challenge
      // Note: canOpenURL is unreliable on Android 11+ without manifest queries declaration
      // Just try to open directly and let it fail if Vinzrik isn't installed
      const pairingUrl = `vinzrik://pair?challenge=${encodeURIComponent(challenge)}`;
      console.log('[SECURITY] Opening Vinzrik with URL:', pairingUrl);

      await Linking.openURL(pairingUrl);
      Alert.alert(
        'Pairing Started',
        'Complete the pairing in Vinzrik. Once done, you can use fingerprint login from Vinzrik.'
      );
    } catch (err: any) {
      Alert.alert('Pairing Error', err.message);
    } finally {
      setPairingDawgTag(false);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Hardware Security</Text>
        <Text style={styles.description}>Manage your physical device keys.</Text>

        {loadingKeys ? (
          <ActivityIndicator color="#4CAF50" style={{ marginVertical: 10 }} />
        ) : (
          <View style={styles.keyList}>
            {passkeys.map(key => (
              <View key={key.id} style={styles.keyItem}>
                <View style={styles.keyInfo}>
                  <Text style={styles.keyName}>{key.device_name}</Text>
                  <Text style={styles.keyMeta}>{new Date(key.created_at).toLocaleDateString()}</Text>
                </View>
                <TouchableOpacity onPress={() => handleDeletePasskey(key.id, key.device_name)}>
                  <Text style={styles.deleteText}>Delete</Text>
                </TouchableOpacity>
              </View>
            ))}
            {passkeys.length === 0 && <Text style={styles.emptyText}>No devices linked yet.</Text>}
          </View>
        )}

        <TouchableOpacity
          style={[styles.linkButton, linkingDevice && styles.buttonDisabled]}
          onPress={handleLinkDevice}
          disabled={linkingDevice}
        >
          {linkingDevice ? <ActivityIndicator color="#fff" /> : <Text style={styles.linkButtonText}>Link This Device</Text>}
        </TouchableOpacity>

        {hasLocalPasskey && (
          <TouchableOpacity
            style={[styles.clearButton, clearingPasskey && styles.buttonDisabled]}
            onPress={handleClearPasskey}
            disabled={clearingPasskey}
          >
            {clearingPasskey ? <ActivityIndicator color="#ff6b6b" /> : <Text style={styles.clearButtonText}>Clear Stored Passkey</Text>}
          </TouchableOpacity>
        )}
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Paired Apps</Text>
        <Text style={styles.description}>
          Pair Vinzrik to enable fingerprint login from your privacy wallet.
        </Text>

        <TouchableOpacity
          style={[styles.linkButton, pairingDawgTag && styles.buttonDisabled]}
          onPress={handlePairDawgTag}
          disabled={pairingDawgTag}
        >
          {pairingDawgTag ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.linkButtonText}>Pair Vinzrik</Text>
          )}
        </TouchableOpacity>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Change Password</Text>
        <TextInput style={styles.input} value={newPassword} onChangeText={setNewPassword} placeholder="New Password" secureTextEntry />
        <TextInput style={styles.input} value={confirmPassword} onChangeText={setConfirmPassword} placeholder="Confirm" secureTextEntry />
        <TouchableOpacity style={styles.saveButton} onPress={handleChangePassword} disabled={changingPassword}>
          <Text style={styles.saveButtonText}>Update Password</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#1a1a2e', padding: 16 },
  card: { backgroundColor: '#252542', borderRadius: 12, padding: 20, marginBottom: 16 },
  cardTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff', marginBottom: 16 },
  description: { fontSize: 14, color: '#888', marginBottom: 20 },
  keyList: { marginBottom: 20 },
  keyItem: { paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: '#333', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  keyInfo: { flex: 1 },
  deleteText: { color: '#ff6b6b', fontSize: 14 },
  keyName: { color: '#fff', fontSize: 15 },
  keyMeta: { color: '#666', fontSize: 12 },
  emptyText: { color: '#666', fontStyle: 'italic', textAlign: 'center' },
  linkButton: { backgroundColor: '#4CAF50', borderRadius: 8, padding: 16, alignItems: 'center' },
  linkButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  input: { backgroundColor: '#1a1a2e', borderRadius: 8, padding: 12, color: '#fff', marginBottom: 12, borderWidth: 1, borderColor: '#333' },
  saveButton: { backgroundColor: 'transparent', borderWidth: 1, borderColor: '#4CAF50', borderRadius: 8, padding: 16, alignItems: 'center' },
  saveButtonText: { color: '#4CAF50', fontSize: 16 },
  buttonDisabled: { opacity: 0.6 },
  clearButton: { backgroundColor: 'transparent', borderWidth: 1, borderColor: '#ff6b6b', borderRadius: 8, padding: 16, alignItems: 'center', marginTop: 12 },
  clearButtonText: { color: '#ff6b6b', fontSize: 16, fontWeight: '600' },
});
