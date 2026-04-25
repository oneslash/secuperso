import React from 'react';
import { View, Text, ActivityIndicator, Pressable, StyleSheet } from 'react-native';
import { Spacing, Colors, Typography } from '@ui/theme/designTokens';
import type { ProviderID, ConnectionState } from '@domain/models';
import { providerDisplayName } from '@domain/models';

const SCHEME = 'light';

interface MockOAuthSheetProps {
  provider: ProviderID;
  state: ConnectionState | null;
  message: string;
  onDismiss: () => void;
}

export const MockOAuthSheet: React.FC<MockOAuthSheetProps> = ({ provider, state, message, onDismiss }) => (
  <View style={styles.scrim}>
    <View style={styles.container}>
      <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Connection flow</Text>
      <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>
        Connecting {providerDisplayName(provider)}
      </Text>
      <View style={styles.statusRow}>
        {state === 'connecting' && <ActivityIndicator size="small" color={Colors.brandTealDeep} />}
        <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{message}</Text>
      </View>
      {state !== 'connecting' && (
        <Pressable style={styles.dismissButton} onPress={onDismiss}>
          <Text style={[Typography.captionStrong, { color: Colors.white }]}>Close</Text>
        </Pressable>
      )}
    </View>
  </View>
);

const styles = StyleSheet.create({
  scrim: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: Colors.overlay[SCHEME],
    alignItems: 'center',
    justifyContent: 'center',
    padding: Spacing.xl,
  },
  container: {
    width: '100%',
    maxWidth: 420,
    padding: Spacing.xl,
    gap: Spacing.m,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  statusRow: { flexDirection: 'row', alignItems: 'center', gap: Spacing.s },
  dismissButton: {
    alignSelf: 'flex-start',
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.s,
    backgroundColor: Colors.brandTealDeep,
    borderRadius: 999,
  },
});
