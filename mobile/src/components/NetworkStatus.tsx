import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, Animated } from 'react-native';
import NetInfo, { NetInfoState } from '@react-native-community/netinfo';

/**
 * Network Status Banner - Shows when device is offline
 * Automatically hides when connection is restored.
 */
export function NetworkStatusBanner() {
  const [isConnected, setIsConnected] = useState<boolean | null>(true);
  const [slideAnim] = useState(new Animated.Value(-50));

  useEffect(() => {
    const unsubscribe = NetInfo.addEventListener((state: NetInfoState) => {
      setIsConnected(state.isConnected);
    });

    return () => unsubscribe();
  }, []);

  useEffect(() => {
    Animated.timing(slideAnim, {
      toValue: isConnected === false ? 0 : -50,
      duration: 300,
      useNativeDriver: true,
    }).start();
  }, [isConnected]);

  // Don't render anything if connected or unknown
  if (isConnected !== false) {
    return null;
  }

  return (
    <Animated.View
      style={[
        styles.banner,
        { transform: [{ translateY: slideAnim }] },
      ]}
    >
      <Text style={styles.text}>No internet connection</Text>
    </Animated.View>
  );
}

/**
 * Hook to check network status
 */
export function useNetworkStatus() {
  const [isConnected, setIsConnected] = useState<boolean | null>(true);
  const [isInternetReachable, setIsInternetReachable] = useState<boolean | null>(true);

  useEffect(() => {
    const unsubscribe = NetInfo.addEventListener((state: NetInfoState) => {
      setIsConnected(state.isConnected);
      setIsInternetReachable(state.isInternetReachable);
    });

    return () => unsubscribe();
  }, []);

  return { isConnected, isInternetReachable };
}

const styles = StyleSheet.create({
  banner: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    backgroundColor: '#f44336',
    paddingVertical: 8,
    paddingHorizontal: 16,
    zIndex: 1000,
  },
  text: {
    color: '#fff',
    fontSize: 14,
    textAlign: 'center',
    fontWeight: '500',
  },
});
