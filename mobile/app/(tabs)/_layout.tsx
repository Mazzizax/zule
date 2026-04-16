import { Tabs } from 'expo-router'

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        tabBarStyle: { backgroundColor: '#1a1a2e', borderTopColor: '#333' },
        tabBarActiveTintColor: '#4fc3f7',
        tabBarInactiveTintColor: '#666',
        headerStyle: { backgroundColor: '#1a1a2e' },
        headerTintColor: '#fff',
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Auth Requests',
          tabBarLabel: 'Requests',
        }}
      />
      <Tabs.Screen
        name="machines"
        options={{
          title: 'Machines',
          tabBarLabel: 'Machines',
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: 'Settings',
          tabBarLabel: 'Settings',
        }}
      />
    </Tabs>
  )
}
