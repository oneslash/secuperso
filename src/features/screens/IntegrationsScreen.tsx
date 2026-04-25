import React, { useEffect } from 'react';
import { View, Text, FlatList, Pressable, StyleSheet, useWindowDimensions } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { StatusPill } from '@ui/components/StatusPill';
import type { AccountCardSummary } from '../stores/securityConsoleStore';
import type { ProviderID, ConnectionState } from '@domain/models';

const SCHEME = 'light';

const STATE_LABELS: Record<ConnectionState, { text: string; tone: 'neutral' | 'positive' | 'caution' | 'critical' }> = {
  connected: { text: 'Connected', tone: 'positive' },
  connecting: { text: 'Connecting', tone: 'caution' },
  disconnected: { text: 'Disconnected', tone: 'neutral' },
  error: { text: 'Error', tone: 'critical' },
};

interface IntegrationsScreenProps {
  accountCards: AccountCardSummary[];
  selectedProviderID: ProviderID | null;
  oauthSheetProvider: ProviderID | null;
  oauthState: ConnectionState | null;
  oauthStatusMessage: string;
  onBeginConnectFlow: (provider: ProviderID) => void;
  onDisconnect: (provider: ProviderID) => void;
  onSelectProvider: (id: ProviderID | null) => void;
  onDismissOAuthSheet: () => void;
}

export const IntegrationsScreen: React.FC<IntegrationsScreenProps> = ({
  accountCards,
  selectedProviderID,
  onBeginConnectFlow,
  onDisconnect,
  onSelectProvider,
}) => {
  const { width } = useWindowDimensions();
  const isStacked = width < 1120;
  const selectedItem = selectedProviderID
    ? accountCards.find((c) => c.providerID === selectedProviderID)
    : null;
  const connectedCount = accountCards.filter((c) => c.connectionState === 'connected').length;

  useEffect(() => {
    if (!selectedProviderID && accountCards.length > 0) {
      onSelectProvider(accountCards[0].providerID);
    }
  }, [accountCards, onSelectProvider, selectedProviderID]);

  return (
    <View style={styles.container}>
      <View style={[styles.hero, isStacked && styles.heroStacked]}>
        <View style={styles.heroCopy}>
          <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Connected accounts</Text>
          <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>See what is covered and what is still missing</Text>
          <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
            Link the services you use most often so your security picture feels more complete and less guess-based.
          </Text>
        </View>
        <View style={styles.coverageSummary}>
          <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Coverage</Text>
          <Text style={[Typography.heroScore, { color: Colors.textPrimary[SCHEME] }]}>{connectedCount}/{accountCards.length}</Text>
          <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>
            {connectedCount === accountCards.length ? 'Everything listed is connected.' : 'A few gaps are still open.'}
          </Text>
        </View>
      </View>

      <View style={[styles.workspace, isStacked && styles.workspaceStacked]}>
        <View style={styles.listPanel}>
          <View style={styles.sectionHeader}>
            <View style={styles.sectionHeadingCopy}>
              <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Providers</Text>
              <Text style={[Typography.headlineMedium, { color: Colors.textPrimary[SCHEME] }]}>Services you can connect</Text>
            </View>
          </View>
          <FlatList
            data={accountCards}
            keyExtractor={(item) => item.providerID}
            renderItem={({ item }) => {
              const stateConfig = STATE_LABELS[item.connectionState];
              return (
                <Pressable
                  style={({ hovered, pressed }: any) => [
                    styles.providerCard,
                    selectedProviderID === item.providerID && styles.providerCardSelected,
                    hovered && styles.providerCardHovered,
                    pressed && styles.providerCardPressed,
                  ]}
                  onPress={() => onSelectProvider(item.providerID)}
                >
                  <View style={styles.providerInfo}>
                    <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>{item.providerName}</Text>
                    <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{item.details}</Text>
                  </View>
                  <StatusPill text={stateConfig.text} tone={stateConfig.tone} />
                </Pressable>
              );
            }}
          />
        </View>
        <View style={styles.inspectorPanel}>
          {selectedItem ? (
            <View style={styles.inspectorContent}>
              <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>Selected provider</Text>
              <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>{selectedItem.providerName}</Text>
              <StatusPill text={STATE_LABELS[selectedItem.connectionState].text} tone={STATE_LABELS[selectedItem.connectionState].tone} />
              <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{selectedItem.details}</Text>
              {selectedItem.latestLoginSummary && (
                <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
                  Last login: {selectedItem.latestLoginSummary}
                </Text>
              )}
              {selectedItem.suspiciousLoginCount > 0 && (
                <Text style={[Typography.captionStrong, { color: Colors.riskRed }]}>
                  {selectedItem.suspiciousLoginCount} suspicious sign-in(s)
                </Text>
              )}
              {selectedItem.connectionState !== 'connected' ? (
                <Pressable
                  style={({ hovered, pressed }: any) => [
                    styles.connectButton,
                    hovered && styles.connectButtonHovered,
                    pressed && styles.connectButtonPressed,
                  ]}
                  onPress={() => onBeginConnectFlow(selectedItem.providerID)}
                >
                  <Text style={[Typography.captionStrong, { color: Colors.white }]}>Connect this provider</Text>
                </Pressable>
              ) : (
                <Pressable
                  style={({ hovered, pressed }: any) => [
                    styles.disconnectButton,
                    hovered && styles.disconnectButtonHovered,
                    pressed && styles.connectButtonPressed,
                  ]}
                  onPress={() => onDisconnect(selectedItem.providerID)}
                >
                  <Text style={[Typography.captionStrong, { color: Colors.riskRed }]}>Disconnect</Text>
                </Pressable>
              )}
            </View>
          ) : (
            <View>
              <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Select a provider</Text>
              <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Choose a provider to connect or review.</Text>
            </View>
          )}
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: Spacing.xl,
    gap: Spacing.l,
    backgroundColor: Colors.canvas[SCHEME],
  },
  hero: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: Spacing.xl,
    padding: Spacing.xl,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  heroStacked: {
    flexDirection: 'column',
  },
  heroCopy: {
    flex: 1,
    maxWidth: 700,
    gap: Spacing.s,
  },
  coverageSummary: {
    width: 280,
    maxWidth: '100%',
    padding: Spacing.l,
    gap: Spacing.s,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: '#B9DDD6',
    backgroundColor: Colors.brandTealMist,
  },
  workspace: {
    flex: 1,
    flexDirection: 'row',
    gap: Spacing.l,
  },
  workspaceStacked: {
    flexDirection: 'column',
  },
  listPanel: {
    flex: 1,
    minWidth: 320,
    padding: Spacing.l,
    gap: Spacing.m,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    gap: Spacing.s,
  },
  sectionHeadingCopy: {
    flex: 1,
    gap: 4,
  },
  providerCard: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: Spacing.s,
    paddingVertical: Spacing.m,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle[SCHEME],
  },
  providerCardSelected: {
    backgroundColor: Colors.surfaceAccent[SCHEME],
    marginHorizontal: -Spacing.s,
    paddingHorizontal: Spacing.s,
    borderRadius: 16,
    borderTopColor: Colors.surfaceAccent[SCHEME],
  },
  providerCardHovered: {
    opacity: 0.94,
  },
  providerCardPressed: {
    opacity: 0.88,
  },
  providerInfo: {
    flex: 1,
    gap: 4,
  },
  inspectorPanel: {
    flex: 1.05,
    padding: Spacing.l,
    gap: Spacing.m,
    borderRadius: Dimensions.panelCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  inspectorContent: {
    gap: Spacing.s,
  },
  connectButton: {
    marginTop: Spacing.s,
    alignSelf: 'flex-start',
    paddingHorizontal: Spacing.l,
    paddingVertical: Spacing.s,
    borderRadius: 999,
    backgroundColor: Colors.brandTealDeep,
  },
  connectButtonHovered: {
    backgroundColor: Colors.brandTeal,
  },
  connectButtonPressed: {
    opacity: 0.9,
  },
  disconnectButton: {
    marginTop: Spacing.s,
    alignSelf: 'flex-start',
    paddingHorizontal: Spacing.l,
    paddingVertical: Spacing.s,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: '#F0B9C1',
    backgroundColor: Colors.riskRedSoft,
  },
  disconnectButtonHovered: {
    borderColor: '#E68694',
  },
});
