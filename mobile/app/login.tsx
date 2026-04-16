import React, { useState } from 'react'
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from 'react-native'
import { router } from 'expo-router'
import { supabase } from '../src/lib/supabase'

export default function LoginScreen() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async () => {
    if (!email || !password) {
      Alert.alert('Error', 'Email and password are required')
      return
    }

    setLoading(true)
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password })
      if (error) throw error
      router.replace('/(tabs)')
    } catch (err: any) {
      Alert.alert('Login Failed', err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Zule</Text>
      <Text style={styles.subtitle}>Authentication Surface</Text>

      <TextInput
        style={styles.input}
        placeholder="Email"
        placeholderTextColor="#666"
        value={email}
        onChangeText={setEmail}
        autoCapitalize="none"
        keyboardType="email-address"
      />

      <TextInput
        style={styles.input}
        placeholder="Password"
        placeholderTextColor="#666"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />

      <TouchableOpacity
        style={[styles.button, loading && styles.buttonDisabled]}
        onPress={handleLogin}
        disabled={loading}
      >
        <Text style={styles.buttonText}>
          {loading ? 'Signing in...' : 'Sign In'}
        </Text>
      </TouchableOpacity>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f23',
    justifyContent: 'center',
    padding: 24,
  },
  title: {
    fontSize: 48,
    fontWeight: '700',
    color: '#fff',
    textAlign: 'center',
    marginBottom: 4,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    marginBottom: 48,
  },
  input: {
    backgroundColor: '#1a1a2e',
    color: '#fff',
    borderRadius: 8,
    padding: 16,
    fontSize: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333',
  },
  button: {
    backgroundColor: '#4fc3f7',
    borderRadius: 8,
    padding: 16,
    marginTop: 12,
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  buttonText: {
    color: '#0f0f23',
    fontSize: 16,
    fontWeight: '600',
    textAlign: 'center',
  },
})
