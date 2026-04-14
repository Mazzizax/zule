import { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  AppState,
} from 'react-native';
import { useRouter } from 'expo-router';
import { useAuth } from '../src/contexts/AuthContext';

/**
 * Verify Email Screen for Zule Mobile
 *
 * Shown to authenticated but unverified users.
 * Provides resend verification + back to login.
 */
export default function VerifyEmailScreen() {
  const router = useRouter();
  const { user, resendVerification, signOut, emailVerified, refreshUser } = useAuth();

  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);

  const [checking, setChecking] = useState(false);

  // When app returns to foreground, refresh user to pick up verification
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') {
        refreshUser();
      }
    });
    return () => subscription.remove();
  }, [refreshUser]);

  useEffect(() => {
    if (emailVerified) {
      router.replace('/(tabs)');
    }
  }, [emailVerified]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const handleCheckVerification = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      await refreshUser();
      // If still not verified after refresh, show message
      // (emailVerified effect above handles the redirect if verified)
      setTimeout(() => {
        setChecking(false);
        setError('Email not verified yet. Check your inbox.');
      }, 500);
    } catch (err: any) {
      setError(err.message || 'Failed to check verification status');
      setChecking(false);
    }
  }, [refreshUser]);

  const handleResend = async () => {
    setSending(true);
    setError(null);
    setSent(false);

    try {
      await resendVerification();
      setSent(true);
      setCooldown(60);
    } catch (err: any) {
      setError(err.message || 'Failed to send verification email');
    } finally {
      setSending(false);
    }
  };

  const handleBackToLogin = async () => {
    await signOut();
    router.replace('/login');
  };

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <Text style={styles.title}>VERIFY EMAIL</Text>

        <View style={styles.messageBox}>
          <Text style={styles.messageText}>
            A verification link was sent to{' '}
            <Text style={styles.emailText}>{user?.email}</Text>.
            {'\n\n'}Check your inbox and tap the link to continue.
          </Text>
        </View>

        {error && (
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {sent && !error && (
          <View style={styles.successBox}>
            <Text style={styles.successText}>Verification email sent. Check your inbox.</Text>
          </View>
        )}

        <TouchableOpacity
          style={[styles.button, styles.primaryButton, (sending || cooldown > 0) && styles.buttonDisabled]}
          onPress={handleResend}
          disabled={sending || cooldown > 0}
        >
          {sending ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>
              {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend Verification Email'}
            </Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.button, styles.checkButton, checking && styles.buttonDisabled]}
          onPress={handleCheckVerification}
          disabled={checking}
        >
          {checking ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>I've Verified My Email</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.button, styles.secondaryButton]}
          onPress={handleBackToLogin}
        >
          <Text style={styles.secondaryButtonText}>Back to Login</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a2e',
    padding: 20,
  },
  card: {
    width: '100%',
    maxWidth: 400,
    backgroundColor: '#252542',
    borderRadius: 12,
    padding: 24,
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 20,
    letterSpacing: 4,
  },
  messageBox: {
    width: '100%',
    backgroundColor: 'rgba(76, 175, 80, 0.1)',
    borderRadius: 8,
    padding: 16,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: 'rgba(76, 175, 80, 0.3)',
  },
  messageText: {
    color: '#ccc',
    textAlign: 'center',
    fontSize: 14,
    lineHeight: 20,
  },
  emailText: {
    color: '#fff',
    fontWeight: '600',
  },
  errorBox: {
    width: '100%',
    backgroundColor: 'rgba(244, 67, 54, 0.1)',
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: 'rgba(244, 67, 54, 0.3)',
  },
  errorText: {
    color: '#f44336',
    textAlign: 'center',
  },
  successBox: {
    width: '100%',
    backgroundColor: 'rgba(76, 175, 80, 0.1)',
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: 'rgba(76, 175, 80, 0.3)',
  },
  successText: {
    color: '#4CAF50',
    textAlign: 'center',
  },
  button: {
    width: '100%',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 8,
  },
  primaryButton: {
    backgroundColor: '#4CAF50',
  },
  checkButton: {
    backgroundColor: '#2a5a8a',
  },
  secondaryButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#333',
  },
  buttonDisabled: {
    opacity: 0.6,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  secondaryButtonText: {
    color: '#888',
    fontSize: 16,
  },
});
