import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { View, Text, ActivityIndicator, StyleSheet, Pressable } from 'react-native';
import { Spacing, Colors, Typography } from '@ui/theme/designTokens';
import { createAppServices, type AppServices } from '@data/appContainer';
import { SecurityConsoleView } from '@features/screens/SecurityConsoleView';
import { LocalNotificationManager } from './localNotificationManager';
import type { AppSection } from '@features/stores/securityConsoleStore';
import {
  useSecurityConsoleStore,
  buildAccountCards,
} from '@features/stores/securityConsoleStore';
import { useActivityStore } from '@features/stores/activityStore';
import { useIntegrationsStore } from '@features/stores/integrationsStore';
import { useExposureStore } from '@features/stores/exposureStore';
import type { ConnectionState, LoginEvent, ProviderID } from '@domain/models';

const SCHEME = 'light';

export default function App() {
  const [services, setServices] = useState<AppServices | null>(null);
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  const [selectedSection, setSelectedSection] = useState<AppSection>('overview');
  const notificationManager = React.useRef(new LocalNotificationManager());

  const securityStore = useSecurityConsoleStore();
  const activityStore = useActivityStore();
  const integrationsStore = useIntegrationsStore();
  const exposureStore = useExposureStore();

  const providerAccountCards = useMemo(
    () => buildAccountCards(
      securityStore.providers,
      securityStore.loginEvents,
      securityStore.providerStates
    ),
    [securityStore.providers, securityStore.loginEvents, securityStore.providerStates]
  );

  const signInActivity = useMemo(
    () => buildSignInActivityPoints(securityStore.loginEvents),
    [securityStore.loginEvents]
  );

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const appServices = await createAppServices();
        if (mounted) {
          setServices(appServices);
          setIsBootstrapping(false);
          await notificationManager.current.requestAuthorization();
        }
      } catch (e: any) {
        if (mounted) {
          setBootstrapError(e.message ?? 'Failed to initialize app');
          setIsBootstrapping(false);
        }
      }
    })();
    return () => { mounted = false; };
  }, []);

  useEffect(() => {
    if (!services) return;
    refreshAll();
  }, [services]);

  const refreshAll = useCallback(async () => {
    if (!services) return;

    useSecurityConsoleStore.getState().setRefreshing(true);
    try {
      const [exposures, logins] = await Promise.all([
        services.exposureService.refresh(),
        services.loginActivityService.refresh(),
      ]);

      useSecurityConsoleStore.getState().setExposures(exposures);
      useSecurityConsoleStore.getState().setLoginEvents(logins);

      const incidents = await services.incidentReadableService.list();
      useSecurityConsoleStore.getState().setIncidents(incidents);

      const connections = await services.providerConnectionReadableService.connections();
      const providerStates = Object.fromEntries(
        connections.map((connection) => [connection.id, connection.state])
      ) as Partial<Record<ProviderID, ConnectionState>>;
      useSecurityConsoleStore.getState().setProviderStates(providerStates);

      const providers = await services.providerCatalogService.providers();
      useSecurityConsoleStore.getState().setProviders(providers);

      useSecurityConsoleStore.getState().setLastRefreshAt(new Date().toISOString());

      await notificationManager.current.notifyOnHighRisk(
        useSecurityConsoleStore.getState().riskSnapshot.level
      );
    } catch (e: any) {
      useSecurityConsoleStore.getState().setError({
        context: 'refresh',
        message: e.message ?? 'Unknown error',
        recoverySuggestion: 'Try again later.',
      });
    } finally {
      useSecurityConsoleStore.getState().setRefreshing(false);
    }
  }, [services]);

  const overviewProps = {
    riskScore: securityStore.riskSnapshot.score,
    riskLevel: securityStore.riskSnapshot.level,
    stateLabel: securityStore.overviewSummary.stateLabel,
    headline: securityStore.overviewSummary.headline,
    detail: securityStore.overviewSummary.detail,
    lastRefreshAt: securityStore.lastRefreshAt,
    suspiciousSignInCount: securityStore.overviewSignals.suspiciousSignInCount,
    totalSignInCount: securityStore.loginEvents.length,
    openIncidentCount: securityStore.overviewSignals.openIncidentCount,
    openExposureCount: securityStore.exposureSummary.openCount,
    connectedProviderCount: securityStore.overviewSignals.connectedProviderCount,
    totalProviderCount: securityStore.overviewSignals.totalProviderCount,
    signInActivity,
    riskDrivers: securityStore.overviewRiskDrivers,
    nextAction: securityStore.nextAction,
    activityPreviewItems: securityStore.overviewActivityPreviewItems,
    connectedProviderRows: providerAccountCards,
    isRefreshing: securityStore.isRefreshing,
    hasConnectedProviders: securityStore.overviewSignals.connectedProviderCount > 0,
    hasLoadedSecurityData: securityStore.loginEvents.length > 0 || securityStore.exposures.length > 0 || securityStore.incidents.length > 0,
    onRefresh: refreshAll,
    onNavigate: (section: AppSection) => setSelectedSection(section),
  };

  const activityProps = {
    activityFeed: securityStore.overviewActivityPreviewItems,
    loginEvents: securityStore.loginEvents,
    incidents: securityStore.incidents,
    activityFilter: activityStore.activityFilter,
    activitySearchText: activityStore.activitySearchText,
    selectedActivityItemID: activityStore.selectedActivityItemID,
    isRefreshing: securityStore.isRefreshing,
    onSetActivityFilter: (f: 'needsAttention' | 'all') => useActivityStore.getState().setActivityFilter(f),
    onSetActivitySearchText: (t: string) => useActivityStore.getState().setActivitySearchText(t),
    onSelectActivityItem: (id: string | null) => useActivityStore.getState().setSelectedActivityItemID(id),
    onRequestMarkAsMe: () => {},
    onRequestCreateIncident: () => {},
    onRequestResolveIncident: () => {},
  };

  const exposureProps = {
    exposureFindingRows: securityStore.filteredExposureFindingRows,
    exposureFilter: securityStore.exposureFilter,
    exposureSearchText: securityStore.exposureSearchText,
    selectedExposureFindingID: securityStore.selectedExposureFindingID,
    exposureSummary: securityStore.exposureSummary,
    monitoredEmails: exposureStore.monitoredEmails,
    isUpdatingMonitoredEmails: exposureStore.isUpdatingMonitoredEmails,
    monitoredEmailsFeedback: exposureStore.monitoredEmailsFeedback,
    onSetExposureFilter: (f: 'atRisk' | 'allOpen') => securityStore.setExposureFilter(f),
    onSetExposureSearchText: (t: string) => securityStore.setExposureSearchText(t),
    onSelectExposureFinding: (id: string | null) => securityStore.setSelectedExposureFindingID(id),
    onAddMonitoredEmail: (email: string, hint: any) => {},
    onRemoveMonitoredEmail: (id: string) => {},
    onSetMonitoredEmailEnabled: (id: string, enabled: boolean) => useExposureStore.getState().setMonitoredEmailEnabled(id, enabled),
    isRefreshing: securityStore.isRefreshing,
  };

  const integrationsProps = {
    accountCards: providerAccountCards,
    selectedProviderID: integrationsStore.selectedProviderID,
    oauthSheetProvider: integrationsStore.oauthSheetProvider,
    oauthState: integrationsStore.oauthState,
    oauthStatusMessage: integrationsStore.oauthStatusMessage,
    onBeginConnectFlow: (provider: any) => useIntegrationsStore.getState().beginConnectFlow(provider),
    onDisconnect: (provider: any) => {},
    onSelectProvider: (id: any) => useIntegrationsStore.getState().setSelectedProviderID(id),
    onDismissOAuthSheet: () => useIntegrationsStore.getState().dismissOAuthSheet(),
  };

  const settingsProps = {
    configuration: exposureStore.exposureSourceConfiguration,
    scenario: securityStore.scenario,
    onSaveConfiguration: (config: any) => useExposureStore.getState().setExposureSourceConfiguration(config),
    onSetScenario: (s: any) => {
      securityStore.setScenario(s);
      services?.scenarioControlService.setScenario(s).then(() => refreshAll());
    },
  };

  if (isBootstrapping) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color={Colors.brandTeal} />
        <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME], marginTop: Spacing.m }]}>Setting up secure environment...</Text>
      </View>
    );
  }

  if (bootstrapError) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={[Typography.headlineMedium, { color: Colors.riskRed }]}>Initialization Failed</Text>
        <Text style={[Typography.body, { color: Colors.textSecondary[SCHEME] }]}>{bootstrapError}</Text>
        <Pressable style={styles.retryButton} onPress={() => { setIsBootstrapping(true); setBootstrapError(null); }}>
          <Text style={[Typography.captionStrong, { color: '#FFFFFF' }]}>Retry</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.appRoot}>
      <SecurityConsoleView
        selectedSection={selectedSection}
        onSetSelectedSection={setSelectedSection}
        overviewProps={overviewProps}
        activityProps={activityProps}
        exposureProps={exposureProps}
        integrationsProps={integrationsProps}
        settingsProps={settingsProps}
        badgeCounts={securityStore.sectionBadgeCounts}
        isRefreshing={securityStore.isRefreshing}
        lastRefreshAt={securityStore.lastRefreshAt}
        onRefresh={refreshAll}
        oauthSheetProvider={integrationsStore.oauthSheetProvider}
        oauthState={integrationsStore.oauthState}
        oauthStatusMessage={integrationsStore.oauthStatusMessage}
        onDismissOAuthSheet={() => useIntegrationsStore.getState().dismissOAuthSheet()}
        presentedError={securityStore.presentedError}
        onDismissError={() => securityStore.setError(null)}
      />
    </View>
  );
}

interface SignInActivityPoint {
  label: string;
  value: number;
}

function buildSignInActivityPoints(loginEvents: LoginEvent[]): SignInActivityPoint[] {
  const latestEventTime = loginEvents.reduce<number | null>((latest, event) => {
    const time = new Date(event.occurredAt).getTime();
    if (Number.isNaN(time)) return latest;
    return latest === null ? time : Math.max(latest, time);
  }, null);
  const endDate = latestEventTime ? new Date(latestEventTime) : new Date();
  endDate.setHours(12, 0, 0, 0);

  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date(endDate);
    date.setDate(endDate.getDate() - (6 - index));
    const key = date.toISOString().slice(0, 10);
    const value = loginEvents.filter((event) => event.occurredAt.slice(0, 10) === key).length;

    return {
      label: date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      value,
    };
  });
}

const styles = StyleSheet.create({
  appRoot: {
    flex: 1,
    minHeight: '100%',
    backgroundColor: Colors.canvas[SCHEME],
  },
  loadingContainer: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: Colors.canvas[SCHEME] },
  retryButton: { backgroundColor: Colors.brandTeal, paddingHorizontal: Spacing.l, paddingVertical: Spacing.s, borderRadius: 8, marginTop: Spacing.m },
});
