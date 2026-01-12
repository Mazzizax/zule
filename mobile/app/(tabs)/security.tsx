import { useState } from 'react';
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
import * as LocalAuthentication from 'expo-local-authentication';
import { useAuth } from '../../src/contexts/AuthContext';
import { supabase } from '../../src/lib/supabase';

/**
 * Security Screen
 *
 * Password change, biometric setup, session management
 */
export default function SecurityScreen() {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [changingPassword, setChangingPassword] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState<boolean | null>(null);
  const [biometricEnabled, setBiometricEnabled] = useState(false);

  // Check biometric availability on mount
  useState(() => {
    checkBiometricAvailability();
  });

  const checkBiometricAvailability = async () => {
    const compatible = await LocalAuthentication.hasHardwareAsync();
    const enrolled = await LocalAuthentication.isEnrolledAsync();
    setBiometricAvailable(compatible && enrolled);
  };

  const handleChangePassword = async () => {
    if (!newPassword || !confirmPassword) {
      Alert.alert('Error', 'Please fill in all password fields');
      return;
    }

    if (newPassword !== confirmPassword) {
      Alert.alert('Error', 'New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      Alert.alert('Error', 'Password must be at least 8 characters');
      return;
    }

    setChangingPassword(true);
    try {
      const { error } = await supabase.auth.updateUser({
        password: newPassword,
      });

      if (error) throw error;

      Alert.alert('Success', 'Password updated successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      Alert.alert('Error', err.message || 'Failed to change password');
    } finally {
      setChangingPassword(false);
    }
  };

  const handleEnableBiometric = async () => {
    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Authenticate to enable biometric login',
        fallbackLabel: 'Use password',
      });

      if (result.success) {
        setBiometricEnabled(true);
        Alert.alert('Success', 'Biometric authentication enabled');
      }
    } catch (err: any) {
      Alert.alert('Error', 'Failed to enable biometric authentication');
    }
  };

  const handleDisableBiometric = () => {
    Alert.alert(
      'Disable Biometric',
      'Are you sure you want to disable biometric authentication?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Disable',
          style: 'destructive',
          onPress: () => setBiometricEnabled(false),
        },
      ]
    );
  };

  return (
    <ScrollView style={styles.container}>
      {/* Password Change */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Change Password</Text>

        <View style={styles.field}>
          <Text style={styles.label}>New Password</Text>
          <TextInput
            style={styles.input}
            value={newPassword}
            onChangeText={setNewPassword}
            placeholder="Enter new password"
            placeholderTextColor="#666"
            secureTextEntry
            editable={!changingPassword}
          />
        </View>

        <View style={styles.field}>
          <Text style={styles.label}>Confirm New Password</Text>
          <TextInput
            style={styles.input}
            value={confirmPassword}
            onChangeText={setConfirmPassword}
            placeholder="Confirm new password"
            placeholderTextColor="#666"
            secureTextEntry
            editable={!changingPassword}
          />
        </View>

        <TouchableOpacity
          style={[styles.saveButton, changingPassword && styles.buttonDisabled]}
          onPress={handleChangePassword}
          disabled={changingPassword}
        >
          {changingPassword ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.saveButtonText}>Update Password</Text>
          )}
        </TouchableOpacity>
      </View>

      {/* Biometric Authentication */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Biometric Authentication</Text>

        {biometricAvailable === null ? (
          <ActivityIndicator color="#4CAF50" />
        ) : biometricAvailable ? (
          <>
            <Text style={styles.description}>
              Use fingerprint or face recognition for quick and secure login.
            </Text>

            <View style={styles.biometricRow}>
              <View style={styles.biometricStatus}>
                <View
                  style={[
                    styles.statusDot,
                    biometricEnabled ? styles.statusEnabled : styles.statusDisabled,
                  ]}
                />
                <Text style={styles.statusText}>
                  {biometricEnabled ? 'Enabled' : 'Disabled'}
                </Text>
              </View>

              <TouchableOpacity
                style={[
                  styles.biometricButton,
                  biometricEnabled ? styles.disableButton : styles.enableButton,
                ]}
                onPress={biometricEnabled ? handleDisableBiometric : handleEnableBiometric}
              >
                <Text
                  style={[
                    styles.biometricButtonText,
                    biometricEnabled ? styles.disableButtonText : styles.enableButtonText,
                  ]}
                >
                  {biometricEnabled ? 'Disable' : 'Enable'}
                </Text>
              </TouchableOpacity>
            </View>
          </>
        ) : (
          <Text style={styles.description}>
            Biometric authentication is not available on this device.
          </Text>
        )}
      </View>

      {/* Session Info */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Current Session</Text>

        <View style={styles.sessionInfo}>
          <Text style={styles.label}>Signed in as</Text>
          <Text style={styles.sessionValue}>{user?.email}</Text>
        </View>

        <Text style={styles.hint}>
          Signing out will end this session and require you to log in again.
        </Text>
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
  field: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    color: '#888',
    marginBottom: 8,
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
  description: {
    fontSize: 14,
    color: '#888',
    lineHeight: 20,
    marginBottom: 16,
  },
  biometricRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  biometricStatus: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 8,
  },
  statusEnabled: {
    backgroundColor: '#4CAF50',
  },
  statusDisabled: {
    backgroundColor: '#888',
  },
  statusText: {
    fontSize: 14,
    color: '#fff',
  },
  biometricButton: {
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderRadius: 8,
  },
  enableButton: {
    backgroundColor: '#4CAF50',
  },
  disableButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#f44336',
  },
  biometricButtonText: {
    fontSize: 14,
    fontWeight: '600',
  },
  enableButtonText: {
    color: '#fff',
  },
  disableButtonText: {
    color: '#f44336',
  },
  sessionInfo: {
    marginBottom: 12,
  },
  sessionValue: {
    fontSize: 16,
    color: '#fff',
    marginTop: 4,
  },
  hint: {
    fontSize: 12,
    color: '#666',
  },
});
