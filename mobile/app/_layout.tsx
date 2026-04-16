import { Stack } from 'expo-router'
import { AuthProvider } from '../src/contexts/AuthContext'
import { StatusBar } from 'expo-status-bar'

export default function RootLayout() {
  return (
    <AuthProvider>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: '#1a1a2e' },
          headerTintColor: '#fff',
          contentStyle: { backgroundColor: '#0f0f23' },
        }}
      >
        <Stack.Screen name="index" options={{ headerShown: false }} />
        <Stack.Screen name="login" options={{ title: 'Sign In', headerShown: false }} />
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
      </Stack>
    </AuthProvider>
  )
}
