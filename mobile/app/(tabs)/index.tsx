/**
 * Auth Requests Screen — Home
 *
 * Shows pending machine login sessions. Tap to approve with biometric.
 * Polls every 3 seconds and subscribes to Supabase Realtime for instant updates.
 */

import React, { useEffect, useState, useCallback } from 'react'
import {
  View, Text, FlatList, TouchableOpacity, StyleSheet,
  RefreshControl, Alert, ActivityIndicator,
} from 'react-native'
import { fetchPendingSessions, getApprovalChallenge, approveSession, denySession } from '../../src/lib/api'
import { authenticateWithPasskey, getStoredCredentialId } from '../../src/lib/passkey'
import { supabase } from '../../src/lib/supabase'
import type { PendingSession } from '../../src/lib/api'

export default function AuthRequestsScreen() {
  const [sessions, setSessions] = useState<PendingSession[]>([])
  const [refreshing, setRefreshing] = useState(false)
  const [approving, setApproving] = useState<string | null>(null)

  const loadSessions = useCallback(async () => {
    try {
      const data = await fetchPendingSessions()
      setSessions(data)
    } catch {
      // Silently fail on poll — will retry
    }
  }, [])

  // Poll every 3 seconds
  useEffect(() => {
    loadSessions()
    const interval = setInterval(loadSessions, 3000)
    return () => clearInterval(interval)
  }, [loadSessions])

  // Supabase Realtime for instant updates
  useEffect(() => {
    const channel = supabase
      .channel('machine-sessions')
      .on('postgres_changes', {
        event: 'INSERT',
        schema: 'public',
        table: 'machine_login_sessions',
      }, () => {
        loadSessions()
      })
      .subscribe()

    return () => { supabase.removeChannel(channel) }
  }, [loadSessions])

  const onRefresh = async () => {
    setRefreshing(true)
    await loadSessions()
    setRefreshing(false)
  }

  const handleApprove = async (session: PendingSession) => {
    setApproving(session.session_id)
    try {
      // Get stored credential ID
      const credentialId = await getStoredCredentialId()
      if (!credentialId) {
        Alert.alert('No Passkey', 'Register a passkey in Zule web first.')
        return
      }

      // Get challenge from server
      const challengeData = await getApprovalChallenge(session.session_id, credentialId)

      // Authenticate with biometric (passkey)
      const assertion = await authenticateWithPasskey({
        challenge: challengeData.options.challenge,
        rpId: challengeData.rp_id,
        timeout: challengeData.options.timeout,
        allowCredentials: challengeData.options.allowCredentials,
        userVerification: challengeData.options.userVerification,
      })

      // Submit approval
      await approveSession(session.session_id, challengeData.challenge_key, assertion)

      Alert.alert('Approved', `${session.machine_name} unlocked`)
      loadSessions()
    } catch (err: any) {
      if (err.message?.includes('cancelled') || err.message?.includes('canceled')) {
        // User cancelled biometric — do nothing
        return
      }
      Alert.alert('Error', err.message || 'Failed to approve')
    } finally {
      setApproving(null)
    }
  }

  const handleDeny = async (session: PendingSession) => {
    try {
      await denySession(session.session_id)
      loadSessions()
    } catch (err: any) {
      Alert.alert('Error', err.message || 'Failed to deny')
    }
  }

  const renderSession = ({ item }: { item: PendingSession }) => {
    const expiresAt = new Date(item.expires_at)
    const secondsLeft = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000))
    const isApproving = approving === item.session_id

    return (
      <View style={styles.card}>
        <Text style={styles.machineName}>{item.machine_name}</Text>
        <Text style={styles.sessionCode}>{item.session_code}</Text>
        <Text style={styles.timer}>
          {secondsLeft > 0 ? `${secondsLeft}s remaining` : 'Expiring...'}
        </Text>

        <View style={styles.actions}>
          <TouchableOpacity
            style={[styles.approveButton, isApproving && styles.buttonDisabled]}
            onPress={() => handleApprove(item)}
            disabled={isApproving}
          >
            {isApproving ? (
              <ActivityIndicator color="#0f0f23" />
            ) : (
              <Text style={styles.approveText}>Approve</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.denyButton}
            onPress={() => handleDeny(item)}
            disabled={isApproving}
          >
            <Text style={styles.denyText}>Deny</Text>
          </TouchableOpacity>
        </View>
      </View>
    )
  }

  return (
    <View style={styles.container}>
      {sessions.length === 0 ? (
        <View style={styles.empty}>
          <Text style={styles.emptyTitle}>No pending requests</Text>
          <Text style={styles.emptySubtitle}>
            Lock a fleet machine and click the Zule tile to begin
          </Text>
        </View>
      ) : (
        <FlatList
          data={sessions}
          keyExtractor={(item) => item.session_id}
          renderItem={renderSession}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#4fc3f7" />
          }
          contentContainerStyle={{ padding: 16 }}
        />
      )}
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f23',
  },
  empty: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 24,
  },
  emptyTitle: {
    fontSize: 20,
    color: '#fff',
    fontWeight: '600',
    marginBottom: 8,
  },
  emptySubtitle: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
  },
  card: {
    backgroundColor: '#1a1a2e',
    borderRadius: 12,
    padding: 20,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333',
  },
  machineName: {
    fontSize: 18,
    color: '#fff',
    fontWeight: '600',
    marginBottom: 8,
  },
  sessionCode: {
    fontSize: 28,
    color: '#4fc3f7',
    fontWeight: '700',
    letterSpacing: 2,
    textAlign: 'center',
    marginVertical: 12,
  },
  timer: {
    fontSize: 14,
    color: '#888',
    textAlign: 'center',
    marginBottom: 16,
  },
  actions: {
    flexDirection: 'row',
    gap: 12,
  },
  approveButton: {
    flex: 1,
    backgroundColor: '#4fc3f7',
    borderRadius: 8,
    padding: 14,
    alignItems: 'center',
  },
  denyButton: {
    paddingHorizontal: 20,
    paddingVertical: 14,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#666',
    alignItems: 'center',
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  approveText: {
    color: '#0f0f23',
    fontSize: 16,
    fontWeight: '600',
  },
  denyText: {
    color: '#666',
    fontSize: 16,
  },
})
