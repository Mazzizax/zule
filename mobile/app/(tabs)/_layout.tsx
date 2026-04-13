import { Tabs } from 'expo-router';
import { useAuth } from '../../src/contexts/AuthContext';
import { useEffect } from 'react';
import { useRouter } from 'expo-router';

/**
 * Tabs Layout for authenticated screens
 *
 * Dashboard | Profile | Security
 */
export default function TabsLayout() {
  const { session, loading, emailVerified } = useAuth();
  const router = useRouter();

  // Redirect to login if not authenticated, or verify-email if unverified
  useEffect(() => {
    if (!loading) {
      if (!session) {
        router.replace('/login');
      } else if (!emailVerified) {
        router.replace('/verify-email');
      }
    }
  }, [session, loading, emailVerified]);

  return (
    <Tabs
      screenOptions={{
        tabBarStyle: {
          backgroundColor: '#252542',
          borderTopColor: '#333',
        },
        tabBarActiveTintColor: '#4CAF50',
        tabBarInactiveTintColor: '#888',
        headerStyle: {
          backgroundColor: '#1a1a2e',
        },
        headerTintColor: '#fff',
        headerTitleStyle: {
          fontWeight: 'bold',
        },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Dashboard',
          tabBarLabel: 'Home',
        }}
      />
      <Tabs.Screen
        name="profile"
        options={{
          title: 'Profile',
          tabBarLabel: 'Profile',
        }}
      />
      <Tabs.Screen
        name="security"
        options={{
          title: 'Security',
          tabBarLabel: 'Security',
        }}
      />
    </Tabs>
  );
}
