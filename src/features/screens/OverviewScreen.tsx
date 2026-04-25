import React, { useState } from 'react';
import { View, ScrollView, Text, Pressable, RefreshControl, StyleSheet, useWindowDimensions, type LayoutChangeEvent } from 'react-native';
import { Spacing, Colors, Typography, Dimensions } from '@ui/theme/designTokens';
import { LineIcon, type LineIconName } from '@ui/components/LineIcon';
import { StatusPill } from '@ui/components/StatusPill';
import type {
  AppSection,
  OverviewRiskDriver as RiskDriverType,
  ActivityFeedItem as ActivityFeedItemType,
  NextAction,
  AccountCardSummary,
} from '../stores/securityConsoleStore';
import type { ConnectionState, ProviderID } from '@domain/models';

const SCHEME = 'light';

interface SignInActivityPoint {
  label: string;
  value: number;
}

interface OverviewScreenProps {
  riskScore: number;
  riskLevel: string;
  stateLabel: string;
  headline: string;
  detail: string;
  lastRefreshAt: string | null;
  suspiciousSignInCount: number;
  totalSignInCount: number;
  openIncidentCount: number;
  openExposureCount: number;
  connectedProviderCount: number;
  totalProviderCount: number;
  signInActivity: SignInActivityPoint[];
  riskDrivers: RiskDriverType[];
  nextAction: NextAction | null;
  activityPreviewItems: ActivityFeedItemType[];
  connectedProviderRows: AccountCardSummary[];
  isRefreshing: boolean;
  hasConnectedProviders: boolean;
  hasLoadedSecurityData: boolean;
  onRefresh: () => void;
  onNavigate: (section: AppSection) => void;
}

const PROVIDER_MARKS: Record<ProviderID, { label: string; foreground: string; background: string }> = {
  google: { label: 'G', foreground: '#0A7AFF', background: '#E8F1FF' },
  outlook: { label: 'M', foreground: '#2563EB', background: '#E0EDFF' },
  other: { label: 'O', foreground: '#111827', background: '#F1F2F4' },
};

const PROVIDER_STATE: Record<ConnectionState, { text: string; tone: 'neutral' | 'positive' | 'caution' | 'critical' }> = {
  connected: { text: 'Secure', tone: 'positive' },
  connecting: { text: 'Connecting', tone: 'caution' },
  disconnected: { text: 'Disconnected', tone: 'neutral' },
  error: { text: 'Review', tone: 'critical' },
};

export const OverviewScreen: React.FC<OverviewScreenProps> = ({
  riskScore,
  riskLevel,
  stateLabel,
  headline,
  detail,
  lastRefreshAt,
  suspiciousSignInCount,
  totalSignInCount,
  openIncidentCount,
  openExposureCount,
  connectedProviderCount,
  totalProviderCount,
  signInActivity,
  riskDrivers,
  nextAction,
  activityPreviewItems,
  connectedProviderRows,
  isRefreshing,
  hasConnectedProviders,
  hasLoadedSecurityData,
  onRefresh,
  onNavigate,
}) => {
  const { width } = useWindowDimensions();
  const isNarrow = width < 1060;
  const isPhone = width < 760;
  const riskMeta = getRiskMeta(riskLevel);
  const flaggedDrivers = riskDrivers.filter((d) => d.emphasis !== 'calm');
  const primaryActionSection = nextAction?.destinationSection ?? 'activity';
  const primaryActionLabel = nextAction?.buttonTitle ?? 'Review activity';
  const activeProviderRows = connectedProviderRows.length > 0
    ? connectedProviderRows
    : buildFallbackProviders(totalProviderCount);

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={[styles.content, isPhone && styles.contentPhone]}
      refreshControl={<RefreshControl refreshing={isRefreshing} onRefresh={onRefresh} />}
    >
      <View style={[styles.header, isPhone && styles.headerPhone]}>
        <View style={styles.headerCopy}>
          <Text style={[Typography.headlineLarge, styles.pageTitle]}>Dashboard</Text>
          <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>Your security overview</Text>
        </View>
        <View style={styles.headerMeta}>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>{formatRefreshTime(lastRefreshAt)}</Text>
          <Pressable
            accessibilityLabel="Refresh security overview"
            style={({ hovered, pressed }: any) => [
              styles.iconButton,
              hovered && styles.iconButtonHovered,
              pressed && styles.iconButtonPressed,
            ]}
            onPress={onRefresh}
            disabled={isRefreshing}
          >
            <LineIcon name="refresh-cw" size={17} color={Colors.textSecondary[SCHEME]} />
          </Pressable>
        </View>
      </View>

      <View style={[styles.metricGrid, isPhone && styles.metricGridPhone]}>
        <MetricCard onPress={() => onNavigate(primaryActionSection)}>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Security Score</Text>
          <View style={styles.scoreRow}>
            <View style={[styles.scoreBadge, { backgroundColor: riskMeta.soft }]}>
              <View style={[styles.scoreBadgeRing, { borderColor: riskMeta.color }]}>
                <LineIcon name="shield" size={30} color={riskMeta.color} />
              </View>
            </View>
            <View style={styles.scoreCopy}>
              <Text style={[Typography.heroScore, styles.scoreValue]}>{riskScore}</Text>
              <Text style={[Typography.bodyStrong, { color: riskMeta.color }]}>{riskMeta.label}</Text>
            </View>
          </View>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>{stateLabel}: {headline}</Text>
        </MetricCard>

        <MetricCard onPress={() => onNavigate('activity')}>
          <MetricIcon icon="log-in" color={Colors.brandBlue} background={Colors.brandBlueSoft} />
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Sign-Ins (7d)</Text>
          <Text style={[Typography.headlineLarge, styles.metricValue]}>{totalSignInCount}</Text>
          <ActionLabel label="View all activity" />
        </MetricCard>

        <MetricCard onPress={() => onNavigate('exposure')}>
          <MetricIcon icon="alert-triangle" color={Colors.riskRed} background={Colors.riskRedSoft} />
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Breaches</Text>
          <Text style={[Typography.headlineLarge, styles.metricValue]}>{openExposureCount}</Text>
          <ActionLabel label="View details" />
        </MetricCard>

        <MetricCard onPress={() => onNavigate('integrations')}>
          <MetricIcon icon="users" color={Colors.riskViolet} background={Colors.riskVioletSoft} />
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>Accounts</Text>
          <Text style={[Typography.headlineLarge, styles.metricValue]}>{connectedProviderCount}</Text>
          <ActionLabel label="Manage accounts" />
        </MetricCard>
      </View>

      <View style={[styles.dashboardGrid, isNarrow && styles.dashboardGridStacked]}>
        <View style={styles.chartPanel}>
          <View style={styles.sectionHeader}>
            <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Sign-In Activity (7 days)</Text>
            {suspiciousSignInCount > 0 && (
              <StatusPill text={`${suspiciousSignInCount} unusual`} tone="critical" />
            )}
          </View>
          <SignInActivityChart points={signInActivity} />
        </View>

        <View style={styles.alertPanel}>
          <View style={styles.sectionHeader}>
            <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Recent Alerts</Text>
            <Pressable onPress={() => onNavigate('activity')}>
              <Text style={[Typography.captionStrong, { color: Colors.brandBlue }]}>View all</Text>
            </Pressable>
          </View>
          <View style={styles.alertList}>
            {activityPreviewItems.length > 0 ? (
              activityPreviewItems.map((item) => (
                <RecentAlertRow key={item.id} item={item} />
              ))
            ) : (
              <View style={styles.emptyState}>
                <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>
                  {isRefreshing ? 'Loading recent alerts...' : 'No recent alerts'}
                </Text>
                <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]}>
                  {hasLoadedSecurityData
                    ? 'Your recent checks are clear.'
                    : 'Run a security check to populate this area.'}
                </Text>
              </View>
            )}
          </View>
        </View>
      </View>

      <View style={styles.providersPanel}>
        <View style={styles.sectionHeader}>
          <Text style={[Typography.bodyStrong, { color: Colors.textPrimary[SCHEME] }]}>Connected Providers</Text>
          <Pressable onPress={() => onNavigate('integrations')}>
            <Text style={[Typography.captionStrong, { color: Colors.brandBlue }]}>View all</Text>
          </Pressable>
        </View>
        <View style={[styles.providerRail, isPhone && styles.providerRailPhone]}>
          {activeProviderRows.map((provider) => (
            <ProviderTile key={provider.providerID} provider={provider} />
          ))}
        </View>
      </View>

      {(flaggedDrivers.length > 0 || !hasConnectedProviders || openIncidentCount > 0) && (
        <View style={styles.contextStrip}>
          <View style={styles.contextIcon}>
            <LineIcon name="info" size={17} color={Colors.brandBlue} />
          </View>
          <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>
            {buildContextSummary({
              detail,
              flaggedDrivers,
              hasConnectedProviders,
              openIncidentCount,
              primaryActionLabel,
            })}
          </Text>
        </View>
      )}
    </ScrollView>
  );
};

interface MetricCardProps {
  children: React.ReactNode;
  onPress: () => void;
}

const MetricCard: React.FC<MetricCardProps> = ({ children, onPress }) => (
  <Pressable
    style={({ hovered, pressed }: any) => [
      styles.metricCard,
      hovered && styles.metricCardHovered,
      pressed && styles.metricCardPressed,
    ]}
    onPress={onPress}
  >
    {children}
  </Pressable>
);

interface MetricIconProps {
  icon: LineIconName;
  color: string;
  background: string;
}

const MetricIcon: React.FC<MetricIconProps> = ({ icon, color, background }) => (
  <View style={[styles.metricIcon, { backgroundColor: background }]}>
    <LineIcon name={icon} size={28} color={color} />
  </View>
);

const ActionLabel: React.FC<{ label: string }> = ({ label }) => (
  <View style={styles.actionLabel}>
    <Text style={[Typography.captionStrong, { color: Colors.textPrimary[SCHEME] }]}>{label}</Text>
    <LineIcon name="arrow-right" size={15} color={Colors.textPrimary[SCHEME]} />
  </View>
);

interface RecentAlertRowProps {
  item: ActivityFeedItemType;
}

const RecentAlertRow: React.FC<RecentAlertRowProps> = ({ item }) => {
  const color = item.severity === 'warning'
    ? Colors.riskRed
    : item.severity === 'caution'
      ? Colors.riskAmber
      : Colors.brandBlue;

  return (
    <View style={styles.alertRow}>
      <View style={[styles.alertDot, { backgroundColor: color }]} />
      <View style={styles.alertCopy}>
        <Text style={[Typography.captionStrong, { color: Colors.textPrimary[SCHEME] }]} numberOfLines={1}>{item.title}</Text>
        <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={2}>{item.detail}</Text>
        <Text style={[Typography.caption, { color: Colors.textTertiary[SCHEME] }]}>{new Date(item.date).toLocaleString()}</Text>
      </View>
      <LineIcon name="chevron-right" size={18} color={Colors.textTertiary[SCHEME]} />
    </View>
  );
};

interface ProviderTileProps {
  provider: AccountCardSummary;
}

const ProviderTile: React.FC<ProviderTileProps> = ({ provider }) => {
  const mark = PROVIDER_MARKS[provider.providerID];
  const state = PROVIDER_STATE[provider.connectionState];

  return (
    <View style={styles.providerTile}>
      <View style={[styles.providerMark, { backgroundColor: mark.background }]}>
        <Text style={[Typography.bodyStrong, { color: mark.foreground }]}>{mark.label}</Text>
      </View>
      <View style={styles.providerCopy}>
        <Text style={[Typography.captionStrong, { color: Colors.textPrimary[SCHEME] }]} numberOfLines={1}>{provider.providerName}</Text>
        <Text style={[Typography.caption, { color: Colors.textSecondary[SCHEME] }]} numberOfLines={1}>
          {provider.latestLoginSummary ?? provider.details}
        </Text>
        <StatusPill text={state.text} tone={state.tone} style={styles.providerPill} />
      </View>
    </View>
  );
};

interface SignInActivityChartProps {
  points: SignInActivityPoint[];
}

const SignInActivityChart: React.FC<SignInActivityChartProps> = ({ points }) => {
  const [chartWidth, setChartWidth] = useState(0);
  const onLayout = (event: LayoutChangeEvent) => setChartWidth(event.nativeEvent.layout.width);
  const maxValue = Math.max(5, Math.ceil(Math.max(...points.map((point) => point.value), 1) / 5) * 5);
  const plotHeight = 154;
  const plotTop = 18;
  const axisLeft = 38;
  const axisRight = 16;
  const axisBottom = 30;
  const drawableWidth = Math.max(chartWidth - axisLeft - axisRight, 1);
  const ySteps = [maxValue, maxValue * 0.75, maxValue * 0.5, maxValue * 0.25, 0];
  const chartPoints = points.map((point, index) => {
    const x = axisLeft + (drawableWidth / Math.max(points.length - 1, 1)) * index;
    const y = plotTop + plotHeight - (point.value / maxValue) * plotHeight;
    return { ...point, x, y };
  });
  const segments = chartPoints.slice(0, -1).map((point, index) => {
    const next = chartPoints[index + 1];
    const dx = next.x - point.x;
    const dy = next.y - point.y;
    const length = Math.sqrt(dx * dx + dy * dy);
    const angle = Math.atan2(dy, dx);
    return {
      id: `${point.label}-${next.label}`,
      left: point.x + dx / 2 - length / 2,
      top: point.y + dy / 2 - 1,
      length,
      angle,
    };
  });

  return (
    <View style={styles.chart} onLayout={onLayout}>
      {ySteps.map((value) => {
        const y = plotTop + plotHeight - (value / maxValue) * plotHeight;
        return (
          <View key={value} style={[styles.gridRow, { top: y }]}>
            <Text style={[Typography.micro, styles.gridLabel]}>{Math.round(value)}</Text>
            <View style={styles.gridLine} />
          </View>
        );
      })}
      <View style={[styles.chartWash, { left: axisLeft, right: axisRight, top: plotTop + 42, bottom: axisBottom }]} />
      {segments.map((segment) => (
        <View
          key={segment.id}
          style={[
            styles.chartSegment,
            {
              left: segment.left,
              top: segment.top,
              width: segment.length,
              transform: [{ rotateZ: `${segment.angle}rad` }],
            },
          ]}
        />
      ))}
      {chartPoints.map((point) => (
        <View key={point.label} style={[styles.chartDot, { left: point.x - 4, top: point.y - 4 }]} />
      ))}
      {chartPoints.map((point) => (
        <Text key={`${point.label}-label`} style={[Typography.micro, styles.xAxisLabel, { left: point.x - 25 }]} numberOfLines={1}>
          {point.label}
        </Text>
      ))}
    </View>
  );
};

function getRiskMeta(riskLevel: string): { label: string; color: string; soft: string } {
  if (riskLevel === 'low') {
    return { label: 'Good', color: Colors.brandTeal, soft: Colors.brandTealSoft };
  }
  if (riskLevel === 'medium') {
    return { label: 'Review', color: Colors.riskAmber, soft: Colors.riskAmberSoft };
  }
  return { label: 'Urgent', color: Colors.riskRed, soft: Colors.riskRedSoft };
}

function formatRefreshTime(lastRefreshAt: string | null): string {
  if (!lastRefreshAt) return 'Last updated: Not yet';
  return `Last updated: ${new Date(lastRefreshAt).toLocaleString()}`;
}

function buildFallbackProviders(totalProviderCount: number): AccountCardSummary[] {
  if (totalProviderCount > 0) return [];

  return [
    {
      providerID: 'google',
      providerName: 'Google',
      details: 'Connect Google account monitoring',
      connectionState: 'disconnected',
      suspiciousLoginCount: 0,
      latestLoginAt: null,
      latestLoginSummary: null,
      needsAttention: true,
    },
    {
      providerID: 'outlook',
      providerName: 'Microsoft',
      details: 'Connect Microsoft sign-in monitoring',
      connectionState: 'disconnected',
      suspiciousLoginCount: 0,
      latestLoginAt: null,
      latestLoginSummary: null,
      needsAttention: true,
    },
    {
      providerID: 'other',
      providerName: 'Other',
      details: 'Add another provider',
      connectionState: 'disconnected',
      suspiciousLoginCount: 0,
      latestLoginAt: null,
      latestLoginSummary: null,
      needsAttention: true,
    },
  ];
}

function buildContextSummary({
  detail,
  flaggedDrivers,
  hasConnectedProviders,
  openIncidentCount,
  primaryActionLabel,
}: {
  detail: string;
  flaggedDrivers: RiskDriverType[];
  hasConnectedProviders: boolean;
  openIncidentCount: number;
  primaryActionLabel: string;
}): string {
  if (!hasConnectedProviders) return 'Connect at least one provider to start building a useful security picture.';
  if (openIncidentCount > 0) return `${openIncidentCount} open incident${openIncidentCount === 1 ? '' : 's'} still need a decision.`;
  if (flaggedDrivers.length > 0) return `${flaggedDrivers[0].title}: ${flaggedDrivers[0].detail} ${primaryActionLabel}.`;
  return detail;
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  content: {
    paddingHorizontal: Spacing.xl,
    paddingTop: Spacing.xl,
    paddingBottom: Spacing.xxl,
    gap: Spacing.l,
  },
  contentPhone: {
    paddingHorizontal: Spacing.m,
    paddingTop: Spacing.l,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: Spacing.l,
  },
  headerPhone: {
    flexDirection: 'column',
  },
  headerCopy: {
    gap: 2,
  },
  pageTitle: {
    color: Colors.textPrimary[SCHEME],
    fontSize: 24,
    lineHeight: 30,
  },
  headerMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  iconButton: {
    width: 30,
    height: 30,
    borderRadius: 15,
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconButtonHovered: {
    backgroundColor: Colors.surfaceSecondary[SCHEME],
  },
  iconButtonPressed: {
    opacity: 0.8,
  },
  metricGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: Spacing.m,
  },
  metricGridPhone: {
    flexDirection: 'column',
  },
  metricCard: {
    flex: 1,
    minWidth: 205,
    minHeight: 150,
    justifyContent: 'space-between',
    gap: Spacing.s,
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  metricCardHovered: {
    borderColor: Colors.borderStrong[SCHEME],
    backgroundColor: '#FCFCFD',
  },
  metricCardPressed: {
    opacity: 0.88,
  },
  scoreRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  scoreBadge: {
    width: 68,
    height: 68,
    borderRadius: 34,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scoreBadgeRing: {
    width: 54,
    height: 54,
    borderRadius: 27,
    borderWidth: 3,
    alignItems: 'center',
    justifyContent: 'center',
  },
  scoreCopy: {
    justifyContent: 'center',
  },
  scoreValue: {
    color: Colors.textPrimary[SCHEME],
    fontSize: 34,
    lineHeight: 38,
  },
  metricIcon: {
    width: 54,
    height: 54,
    borderRadius: 27,
    alignItems: 'center',
    justifyContent: 'center',
  },
  metricValue: {
    color: Colors.textPrimary[SCHEME],
    fontSize: 34,
    lineHeight: 38,
  },
  actionLabel: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.xs,
  },
  dashboardGrid: {
    flexDirection: 'row',
    gap: Spacing.m,
  },
  dashboardGridStacked: {
    flexDirection: 'column',
  },
  chartPanel: {
    flex: 1.75,
    minWidth: 0,
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  alertPanel: {
    flex: 1,
    minWidth: 310,
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  sectionHeader: {
    minHeight: 28,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: Spacing.m,
  },
  chart: {
    height: 218,
    marginTop: Spacing.s,
    overflow: 'hidden',
  },
  gridRow: {
    position: 'absolute',
    left: 0,
    right: 0,
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  gridLabel: {
    width: 26,
    color: Colors.textSecondary[SCHEME],
    textAlign: 'right',
  },
  gridLine: {
    flex: 1,
    height: 1,
    backgroundColor: Colors.borderSubtle[SCHEME],
  },
  chartWash: {
    position: 'absolute',
    backgroundColor: Colors.brandBlueSoft,
    opacity: 0.68,
  },
  chartSegment: {
    position: 'absolute',
    height: 2,
    borderRadius: 2,
    backgroundColor: Colors.brandBlue,
  },
  chartDot: {
    position: 'absolute',
    width: 8,
    height: 8,
    borderRadius: 4,
    borderWidth: 2,
    borderColor: Colors.brandBlue,
    backgroundColor: Colors.white,
  },
  xAxisLabel: {
    position: 'absolute',
    bottom: 0,
    width: 50,
    color: Colors.textSecondary[SCHEME],
    textAlign: 'center',
  },
  alertList: {
    marginTop: Spacing.s,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle[SCHEME],
  },
  alertRow: {
    minHeight: 78,
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingVertical: Spacing.s,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle[SCHEME],
  },
  alertDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    alignSelf: 'flex-start',
    marginTop: 8,
  },
  alertCopy: {
    flex: 1,
    gap: 2,
  },
  emptyState: {
    paddingVertical: Spacing.l,
    gap: Spacing.xs,
  },
  providersPanel: {
    padding: Spacing.m,
    borderRadius: Dimensions.cardCornerRadius,
    borderWidth: 1,
    borderColor: Colors.borderSubtle[SCHEME],
    backgroundColor: Colors.surfacePrimary[SCHEME],
  },
  providerRail: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: Spacing.m,
    marginTop: Spacing.m,
  },
  providerRailPhone: {
    flexDirection: 'column',
  },
  providerTile: {
    flex: 1,
    minWidth: 190,
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
  },
  providerMark: {
    width: 36,
    height: 36,
    borderRadius: 10,
    alignItems: 'center',
    justifyContent: 'center',
  },
  providerCopy: {
    flex: 1,
    minWidth: 0,
    gap: 2,
  },
  providerPill: {
    alignSelf: 'flex-start',
    marginTop: 4,
    paddingVertical: 2,
  },
  contextStrip: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.s,
    paddingHorizontal: Spacing.m,
    paddingVertical: Spacing.s,
    borderRadius: Dimensions.cardCornerRadius,
    backgroundColor: Colors.surfaceSecondary[SCHEME],
  },
  contextIcon: {
    width: 28,
    height: 28,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: Colors.brandBlueSoft,
  },
});
