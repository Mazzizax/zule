import React, { useEffect, useState, useCallback } from 'react'
import { View, Text, FlatList, StyleSheet, RefreshControl } from 'react-native'
import { fetchMachines } from '../../src/lib/api'
import type { Machine } from '../../src/lib/api'

export default function MachinesScreen() {
  const [machines, setMachines] = useState<Machine[]>([])
  const [refreshing, setRefreshing] = useState(false)

  const loadMachines = useCallback(async () => {
    try {
      const data = await fetchMachines()
      setMachines(data)
    } catch {
      // Silent
    }
  }, [])

  useEffect(() => {
    loadMachines()
  }, [loadMachines])

  const onRefresh = async () => {
    setRefreshing(true)
    await loadMachines()
    setRefreshing(false)
  }

  const renderMachine = ({ item }: { item: Machine }) => {
    const lastSeen = item.last_seen_at
      ? new Date(item.last_seen_at).toLocaleString()
      : 'Never'

    return (
      <View style={styles.card}>
        <Text style={styles.name}>{item.machine_name}</Text>
        <Text style={styles.identifier}>{item.machine_identifier}</Text>
        <Text style={styles.lastSeen}>Last seen: {lastSeen}</Text>
      </View>
    )
  }

  return (
    <View style={styles.container}>
      {machines.length === 0 ? (
        <View style={styles.empty}>
          <Text style={styles.emptyTitle}>No machines</Text>
          <Text style={styles.emptySubtitle}>
            Register a fleet machine with Zule to see it here
          </Text>
        </View>
      ) : (
        <FlatList
          data={machines}
          keyExtractor={(item) => item.id}
          renderItem={renderMachine}
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
  container: { flex: 1, backgroundColor: '#0f0f23' },
  empty: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24 },
  emptyTitle: { fontSize: 20, color: '#fff', fontWeight: '600', marginBottom: 8 },
  emptySubtitle: { fontSize: 14, color: '#666', textAlign: 'center' },
  card: {
    backgroundColor: '#1a1a2e',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#333',
  },
  name: { fontSize: 18, color: '#fff', fontWeight: '600', marginBottom: 4 },
  identifier: { fontSize: 14, color: '#4fc3f7', marginBottom: 8 },
  lastSeen: { fontSize: 12, color: '#666' },
})
