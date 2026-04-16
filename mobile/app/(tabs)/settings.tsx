import React from 'react'
import { View, Text, TouchableOpacity, StyleSheet, Alert } from 'react-native'
import { router } from 'expo-router'
import { useAuth } from '../../src/contexts/AuthContext'

export default function SettingsScreen() {
  const { user, signOut } = useAuth()

  const handleSignOut = async () => {
    Alert.alert('Sign Out', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Sign Out',
        style: 'destructive',
        onPress: async () => {
          await signOut()
          router.replace('/login')
        },
      },
    ])
  }

  return (
    <View style={styles.container}>
      <View style={styles.section}>
        <Text style={styles.label}>Signed in as</Text>
        <Text style={styles.value}>{user?.email || 'Unknown'}</Text>
      </View>

      <View style={styles.section}>
        <Text style={styles.label}>Version</Text>
        <Text style={styles.value}>Zule Auth 2.0.0</Text>
      </View>

      <TouchableOpacity style={styles.signOutButton} onPress={handleSignOut}>
        <Text style={styles.signOutText}>Sign Out</Text>
      </TouchableOpacity>
    </View>
  )
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0f0f23', padding: 24 },
  section: {
    backgroundColor: '#1a1a2e',
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333',
  },
  label: { fontSize: 12, color: '#666', marginBottom: 4 },
  value: { fontSize: 16, color: '#fff' },
  signOutButton: {
    marginTop: 24,
    padding: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#ff5252',
    alignItems: 'center',
  },
  signOutText: { color: '#ff5252', fontSize: 16, fontWeight: '600' },
})
