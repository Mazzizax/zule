import { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { useLocalSearchParams } from 'expo-router';
import { supabase } from '../src/lib/supabase';
import { issueAttestation, buildCallbackUrl, buildCancelledCallbackUrl } from '../src/lib/attestation';
import { isValidCallbackUrl, openUrl } from '../src/lib/linking';

/**
 * Auth Screen for Dawg Tag Integration
 *
 * This screen handles authentication requests from Dawg Tag.
 * Flow:
 * 1. Dawg Tag opens: https://gatekeeper-nine.vercel.app/auth?callback=dawgtag://auth-callback
 * 2. User logs in with email/password
 * 3. On success, call issue-attestation to get signed JWT
 * 4. Redirect to callback with attestation (NOT user_id)
 *
 * The attestation proves "a valid user authenticated" without revealing identity.
 */
export default function AuthScreen() {
  const params = useLocalSearchParams<{ callback?: string }>();
  const callbackUrl = params.callback || null;

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirecting, setRedirecting] = useState(false);

  const isValidCallback = isValidCallbackUrl(callbackUrl);

  const handleLogin = async () => {
    if (!isValidCallback || !callbackUrl) {
      setError('Invalid callback URL');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // Authenticate with Supabase
      const { data, error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (authError) {
        throw authError;
      }

      if (!data.user || !data.session) {
        throw new Error('Login failed - no user or session returned');
      }

      // Issue attestation
      const { attestation } = await issueAttestation(data.session);

      // Sign out from this session (we only needed to get the attestation)
      await supabase.auth.signOut();

      // Build callback URL and redirect
      const finalUrl = buildCallbackUrl(callbackUrl, attestation);
      setRedirecting(true);

      await openUrl(finalUrl);
    } catch (err: any) {
      setError(err.message || 'Login failed');
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    if (callbackUrl) {
      const cancelUrl = buildCancelledCallbackUrl(callbackUrl);
      setRedirecting(true);
      await openUrl(cancelUrl);
    }
  };

  // Invalid callback state
  if (!isValidCallback) {
    return (
      <View style={styles.container}>
        <View style={styles.card}>
          <Text style={styles.title}>GATEKEEPER</Text>
          <Text style={styles.subtitle}>Authentication Error</Text>
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>
              Invalid or missing callback URL. This screen should be opened from Dawg Tag.
            </Text>
          </View>
        </View>
      </View>
    );
  }

  // Redirecting state
  if (redirecting) {
    return (
      <View style={styles.container}>
        <View style={styles.card}>
          <Text style={styles.title}>GATEKEEPER</Text>
          <Text style={styles.subtitle}>Redirecting to Dawg Tag...</Text>
          <ActivityIndicator size="large" color="#4CAF50" style={styles.spinner} />
        </View>
      </View>
    );
  }

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
    >
      <View style={styles.card}>
        <Text style={styles.title}>GATEKEEPER</Text>
        <Text style={styles.subtitle}>Sign in to continue to your app</Text>

        {error && (
          <View style={styles.errorBox}>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        <TextInput
          style={styles.input}
          placeholder="Email"
          placeholderTextColor="#666"
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          autoComplete="email"
          editable={!loading}
        />

        <TextInput
          style={styles.input}
          placeholder="Password"
          placeholderTextColor="#666"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          autoComplete="password"
          editable={!loading}
        />

        <TouchableOpacity
          style={[styles.button, styles.primaryButton, loading && styles.buttonDisabled]}
          onPress={handleLogin}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Sign In</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.button, styles.secondaryButton]}
          onPress={handleCancel}
          disabled={loading}
        >
          <Text style={styles.secondaryButtonText}>Cancel</Text>
        </TouchableOpacity>

        <Text style={styles.footerText}>
          Your credentials are verified by Gatekeeper.{'\n'}
          Your identity stays private with Dawg Tag.
        </Text>
      </View>
    </KeyboardAvoidingView>
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
    fontSize: 28,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#888',
    marginBottom: 24,
  },
  input: {
    width: '100%',
    height: 50,
    backgroundColor: '#1a1a2e',
    borderRadius: 8,
    paddingHorizontal: 16,
    color: '#fff',
    fontSize: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333',
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
  secondaryButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#666',
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
  spinner: {
    marginTop: 24,
  },
  footerText: {
    color: '#666',
    fontSize: 12,
    textAlign: 'center',
    marginTop: 24,
    lineHeight: 18,
  },
});
