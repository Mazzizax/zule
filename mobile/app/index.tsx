import { useEffect } from 'react';
import { useRouter } from 'expo-router';
import { View, ActivityIndicator, StyleSheet } from 'react-native';
import { useAuth } from '../src/contexts/AuthContext';

/**
 * Index Route - Redirect based on auth state
 *
 * If authenticated: go to dashboard (tabs)
 * If not authenticated: go to login
 */
export default function Index() {
  const { session, loading, emailVerified } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading) {
      if (session) {
        if (emailVerified) {
          router.replace('/(tabs)');
        } else {
          router.replace('/verify-email');
        }
      } else {
        router.replace('/login');
      }
    }
  }, [session, loading, emailVerified]);

  return (
    <View style={styles.container}>
      <ActivityIndicator size="large" color="#4CAF50" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#1a1a2e',
  },
});
