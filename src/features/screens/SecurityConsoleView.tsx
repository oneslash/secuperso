import React from 'react';
import { View, Text, Pressable, StyleSheet, useWindowDimensions } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { LineIcon, type LineIconName } from '@ui/components/LineIcon';
import { OverviewScreen } from './OverviewScreen';
import { ActivityScreen } from './ActivityScreen';
import { ExposureScreen } from './ExposureScreen';
import { IntegrationsScreen } from './IntegrationsScreen';
import { SettingsScreen } from './SettingsScreen';
import { MockOAuthSheet } from './MockOAuthSheet';
import type { AppSection, SectionBadgeCounts } from '../stores/securityConsoleStore';

const SCHEME = 'light';

interface SecurityConsoleViewProps {
  selectedSection: AppSection;
  onSetSelectedSection: (section: AppSection) => void;
  overviewProps: any;
  activityProps: any;
  exposureProps: any;
  integrationsProps: any;
  settingsProps: any;
  badgeCounts: SectionBadgeCounts;
  isRefreshing: boolean;
  lastRefreshAt: string | null;
  onRefresh: () => void;
  oauthSheetProvider: any;
  oauthState: any;
  oauthStatusMessage: string;
  onDismissOAuthSheet: () => void;
  presentedError: { context: string; message: string; recoverySuggestion: string } | null;
  onDismissError: () => void;
}

type NavItem = {
  id: string;
  label: string;
  icon: LineIconName;
  section: AppSection;
  badgeKind?: 'alerts';
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid', section: 'overview' },
  { id: 'sign-ins', label: 'Sign-Ins', icon: 'activity', section: 'activity' },
  { id: 'accounts', label: 'Accounts', icon: 'users', section: 'integrations' },
  { id: 'breaches', label: 'Breaches', icon: 'alert-circle', section: 'exposure' },
  { id: 'providers', label: 'Providers', icon: 'box', section: 'integrations' },
  { id: 'device-security', label: 'Device Security', icon: 'monitor', section: 'settings' },
  { id: 'privacy', label: 'Privacy', icon: 'shield', section: 'settings' },
  { id: 'alerts', label: 'Alerts', icon: 'bell', section: 'activity', badgeKind: 'alerts' },
  { id: 'reports', label: 'Reports', icon: 'clipboard', section: 'overview' },
];

const ACTIVE_NAV_ID: Record<AppSection, string> = {
  overview: 'dashboard',
  activity: 'sign-ins',
  exposure: 'breaches',
  integrations: 'accounts',
  settings: 'privacy',
};

const SECTION_META: Record<AppSection, { label: string; description: string; eyebrow: string }> = {
  overview: {
    label: 'Dashboard',
    description: 'Your security overview',
    eyebrow: 'Security',
  },
  activity: {
    label: 'Sign-Ins',
    description: 'Recent sign-ins and unusual moments',
    eyebrow: 'Activity',
  },
  exposure: {
    label: 'Breaches',
    description: 'Leaks, breach findings, and watched emails',
    eyebrow: 'Exposure',
  },
  integrations: {
    label: 'Accounts',
    description: 'Linked services and provider coverage',
    eyebrow: 'Coverage',
  },
  settings: {
    label: 'Privacy',
    description: 'Local configuration and demo controls',
    eyebrow: 'Preferences',
  },
};

export const SecurityConsoleView: React.FC<SecurityConsoleViewProps> = ({
  selectedSection,
  onSetSelectedSection,
  overviewProps,
  activityProps,
  exposureProps,
  integrationsProps,
  settingsProps,
  badgeCounts,
  isRefreshing,
  lastRefreshAt,
  onRefresh,
  oauthSheetProvider,
  oauthState,
  oauthStatusMessage,
  onDismissOAuthSheet,
  presentedError,
  onDismissError,
}) => {
  const { width } = useWindowDimensions();
  const isCompact = width < 1120;
  const isPhone = width < 760;
  const totalAttentionCount = badgeCounts.activity + badgeCounts.exposure + badgeCounts.integrations;

  const renderSection = () => {
    switch (selectedSection) {
      case 'overview': return <OverviewScreen {...overviewProps} />;
      case 'activity': return <ActivityScreen {...activityProps} />;
      case 'exposure': return <ExposureScreen {...exposureProps} />;
      case 'integrations': return <IntegrationsScreen {...integrationsProps} />;
      case 'settings': return <SettingsScreen {...settingsProps} />;
    }
  };

  return (
    <View style={[styles.container, isPhone && styles.containerPhone]}>
      <View style={[styles.sidebar, isCompact && styles.sidebarCompact, isPhone && styles.sidebarPhone]}>
        <View style={styles.windowControls} />

        <View style={styles.brandRow}>
          <View style={styles.brandMark}>
            <LineIcon name="shield" size={20} color={Colors.white} />
          </View>
          <Text style={[Typography.title, styles.brandText]}>SecuPerso</Text>
        </View>

        <View style={[styles.navGroup, isPhone && styles.navGroupPhone]}>
          {NAV_ITEMS.map((item) => {
            const isSelected = ACTIVE_NAV_ID[selectedSection] === item.id;
            const badgeValue = item.badgeKind === 'alerts' ? totalAttentionCount : 0;

            return (
              <Pressable
                key={item.id}
                style={({ hovered, pressed }: any) => [
                  styles.sidebarItem,
                  isPhone && styles.sidebarItemPhone,
                  isSelected && styles.sidebarItemSelected,
                  hovered && !isSelected && styles.sidebarItemHovered,
                  pressed && styles.sidebarItemPressed,
                ]}
                onPress={() => onSetSelectedSection(item.section)}
              >
                <LineIcon
                  name={item.icon}
                  size={19}
                  color={isSelected ? Colors.white : Colors.textSecondary[SCHEME]}
                />
                <Text
                  style={[
                    Typography.captionStrong,
                    styles.sidebarItemLabel,
                    { color: isSelected ? Colors.white : Colors.textPrimary[SCHEME] },
                  ]}
                  numberOfLines={1}
                >
                  {item.label}
                </Text>
                {badgeValue > 0 && (
                  <View style={styles.badge}>
                    <Text style={[Typography.micro, { color: Colors.white }]}>{badgeValue}</Text>
                  </View>
                )}
              </Pressable>
            );
          })}
        </View>

        <View style={[styles.userRow, isPhone && styles.userRowPhone]}>
          <View style={styles.userAvatar}>
            <Text style={[Typography.captionStrong, { color: Colors.white }]}>JD</Text>
          </View>
          <View style={styles.userCopy}>
            <Text style={[Typography.captionStrong, { color: Colors.textPrimary[SCHEME] }]} numberOfLines={1}>John Doe</Text>
            <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={1}>john.doe@example.com</Text>
          </View>
          <LineIcon name="chevron-down" size={16} color={Colors.textTertiary[SCHEME]} />
        </View>
      </View>

      <View style={styles.detail}>
        {selectedSection !== 'overview' && (
          <View style={styles.toolbar}>
            <View style={styles.toolbarCopy}>
              <Text style={[Typography.overline, { color: Colors.textTertiary[SCHEME] }]}>
                {SECTION_META[selectedSection].eyebrow}
              </Text>
              <Text style={[Typography.headlineLarge, { color: Colors.textPrimary[SCHEME] }]}>
                {SECTION_META[selectedSection].label}
              </Text>
              <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>
                {SECTION_META[selectedSection].description}
              </Text>
            </View>

            <View style={styles.toolbarActions}>
              <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME], textAlign: 'right' }]}>
                {formatRefreshTime(lastRefreshAt)}
              </Text>
              <Pressable
                style={({ hovered, pressed }: any) => [
                  styles.refreshButton,
                  hovered && styles.refreshButtonHovered,
                  pressed && styles.refreshButtonPressed,
                  isRefreshing && styles.refreshButtonDisabled,
                ]}
                onPress={onRefresh}
                disabled={isRefreshing}
              >
                <LineIcon name="refresh-cw" size={16} color={Colors.white} />
                <Text style={[Typography.captionStrong, { color: Colors.white }]}>
                  {isRefreshing ? 'Refreshing...' : 'Refresh'}
                </Text>
              </Pressable>
            </View>
          </View>
        )}

        {presentedError && (
          <View style={styles.errorBanner}>
            <View style={styles.errorBannerCopy}>
              <Text style={[Typography.captionStrong, { color: Colors.riskRed }]}>
                {presentedError.context}
              </Text>
              <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>
                {presentedError.message}
              </Text>
              <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                {presentedError.recoverySuggestion}
              </Text>
            </View>
            <Pressable style={styles.errorDismiss} onPress={onDismissError}>
              <Text style={[Typography.captionStrong, { color: Colors.riskRed }]}>Dismiss</Text>
            </Pressable>
          </View>
        )}

        <View style={styles.content}>{renderSection()}</View>
      </View>

      {oauthSheetProvider && (
        <MockOAuthSheet
          provider={oauthSheetProvider}
          state={oauthState}
          message={oauthStatusMessage}
          onDismiss={onDismissOAuthSheet}
        />
      )}
    </View>
  );
};

function formatRefreshTime(lastRefreshAt: string | null): string {
  if (!lastRefreshAt) return 'No security check has run yet';
  return `Last updated: ${new Date(lastRefreshAt).toLocaleString()}`;
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  containerPhone: {
    flexDirection: 'column',
  },
  sidebar: {
    width: Dimensions.railWidth,
    paddingHorizontal: Spacing.l,
    paddingTop: Spacing.m,
    paddingBottom: Spacing.l,
    gap: Spacing.l,
    borderRightWidth: 1,
    borderRightColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.canvas[SCHEME],
  },
  sidebarCompact: {
    width: 256,
    paddingHorizontal: Spacing.m,
  },
  sidebarPhone: {
    width: '100%',
    maxHeight: 260,
    borderRightWidth: 0,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle[SCHEME],
  },
  windowControls: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    height: 18,
  },
  brandRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingTop: Spacing.s,
  },
  brandMark: {
    width: 34,
    height: 34,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#263B5E',
  },
  brandText: {
    color: Colors.textPrimary[SCHEME],
  },
  navGroup: {
    flex: 1,
    gap: 6,
  },
  navGroupPhone: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    alignContent: 'flex-start',
  },
  sidebarItem: {
    minHeight: 42,
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingHorizontal: Spacing.s,
    paddingVertical: Spacing.xs,
    borderRadius: 6,
  },
  sidebarItemPhone: {
    minWidth: 130,
    flexGrow: 1,
  },
  sidebarItemHovered: {
    backgroundColor: Colors.surfaceTertiary[SCHEME],
  },
  sidebarItemSelected: {
    backgroundColor: Colors.brandBlue,
  },
  sidebarItemPressed: {
    opacity: 0.88,
  },
  sidebarItemLabel: {
    flex: 1,
    fontSize: 14,
    lineHeight: 18,
  },
  badge: {
    minWidth: 20,
    height: 20,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: Colors.riskRed,
  },
  userRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingTop: Spacing.s,
  },
  userRowPhone: {
    display: 'none',
  },
  userAvatar: {
    width: 36,
    height: 36,
    borderRadius: 18,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#5EB38C',
  },
  userCopy: {
    flex: 1,
  },
  detail: {
    flex: 1,
    minWidth: 0,
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  toolbar: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    gap: Spacing.l,
    paddingHorizontal: 28,
    paddingTop: Spacing.l,
    paddingBottom: 20,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  toolbarCopy: {
    flex: 1,
    maxWidth: 620,
    gap: 4,
  },
  toolbarActions: {
    alignItems: 'flex-end',
    gap: Spacing.s,
  },
  refreshButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.xs,
    borderRadius: 6,
    backgroundColor: Colors.brandBlue,
  },
  refreshButtonHovered: {
    backgroundColor: Colors.brandBlueDeep,
  },
  refreshButtonPressed: {
    opacity: 0.9,
  },
  refreshButtonDisabled: {
    opacity: 0.55,
  },
  errorBanner: {
    marginHorizontal: Spacing.xl,
    marginTop: Spacing.l,
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: '#F7B8C0',
    backgroundColor: Colors.riskRedSoft,
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: Spacing.m,
  },
  errorBannerCopy: {
    flex: 1,
    gap: 4,
  },
  errorDismiss: {
    alignSelf: 'flex-start',
    paddingTop: 2,
  },
  content: {
    flex: 1,
  },
});
