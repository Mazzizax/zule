import { Redirect } from 'expo-router'
import { useAuth } from '../src/contexts/AuthContext'
import { ActivityIndicator, View } from 'react-native'

export default function Index() {
  const { session, loading } = useAuth()

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: '#0f0f23' }}>
        <ActivityIndicator size="large" color="#4fc3f7" />
      </View>
    )
  }

  if (session) {
    return <Redirect href="/(tabs)" />
  }

  return <Redirect href="/login" />
}
