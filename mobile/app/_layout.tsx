import { Stack } from 'expo-router';
import { AuthProvider } from '../src/contexts/AuthContext';
import { StatusBar } from 'expo-status-bar';
import { ErrorBoundary } from '../src/components/ErrorBoundary';
import { NetworkStatusBanner } from '../src/components/NetworkStatus';

/**
 * Root Layout for Zule Mobile App
 *
 * Provides authentication context to all screens
 */
export default function RootLayout() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <StatusBar style="light" />
        <NetworkStatusBanner />
        <Stack
          screenOptions={{
            headerStyle: {
              backgroundColor: '#1a1a2e',
            },
            headerTintColor: '#fff',
            headerTitleStyle: {
              fontWeight: 'bold',
            },
            contentStyle: {
              backgroundColor: '#1a1a2e',
            },
          }}
        >
        <Stack.Screen
          name="index"
          options={{
            title: 'Zule',
          }}
        />
        <Stack.Screen
          name="auth"
          options={{
            title: 'Sign In',
            presentation: 'modal',
          }}
        />
        <Stack.Screen
          name="(tabs)"
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="login"
          options={{
            title: 'Sign In',
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="register"
          options={{
            title: 'Create Account',
            headerShown: false,
          }}
        />
        </Stack>
      </AuthProvider>
    </ErrorBoundary>
  );
}
