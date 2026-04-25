import type {
  RiskLevel,
  ExposureSeverity,
  ConnectionState,
  ProviderID,
  ExposureRecord,
  LoginEvent,
  IncidentCase,
  RiskSnapshot,
  ProviderDescriptor,
  ProviderConnection,
  MonitoredEmailAddress,
  ExposureSourceConfiguration,
  ExposureStatus,
  FixtureScenario,
} from '@domain/models';
import { riskScoringEngine } from '@domain/riskScoringEngine';
import { create } from 'zustand';

export type AppSection = 'overview' | 'activity' | 'exposure' | 'integrations' | 'settings';
export const APP_SECTIONS: AppSection[] = ['overview', 'activity', 'exposure', 'integrations', 'settings'];

export type ActivityFeedFilter = 'needsAttention' | 'all';
export type ExposureFindingFilter = 'atRisk' | 'allOpen';

export interface OverviewRiskDriver {
  id: string;
  title: string;
  detail: string;
  emphasis: 'calm' | 'caution' | 'critical';
}

export interface OverviewSummary {
  riskScore: number;
  riskLevel: RiskLevel;
  stateLabel: string;
  headline: string;
  detail: string;
  lastUpdatedAt: string;
}

export interface NextAction {
  kind:
    | { type: 'reviewHighRiskExposure'; exposureID: string }
    | { type: 'reviewSuspiciousLogin'; loginID: string }
    | { type: 'reviewIncident'; incidentID: string }
    | { type: 'connectProvider'; providerID: ProviderID }
    | { type: 'runSecurityCheck' };
  title: string;
  detail: string;
  buttonTitle: string;
  destinationSection: AppSection;
}

export interface AccountCardSummary {
  providerID: ProviderID;
  providerName: string;
  details: string;
  connectionState: ConnectionState;
  suspiciousLoginCount: number;
  latestLoginAt: string | null;
  latestLoginSummary: string | null;
  needsAttention: boolean;
}

export interface ExposureSummary {
  openCount: number;
  highRiskOpenCount: number;
  affectedEmailCount: number;
  mostRecentAt: string | null;
  headline: string;
  detail: string;
}

export interface OverviewSignalsProjection {
  suspiciousSignInCount: number;
  openIncidentCount: number;
  connectedProviderCount: number;
  totalProviderCount: number;
}

export interface SectionBadgeCounts {
  activity: number;
  exposure: number;
  integrations: number;
}

export interface ExposureFindingsProjectionRow {
  id: string;
  email: string;
  source: string;
  foundAt: string;
  severity: ExposureSeverity;
  remediation: string;
}

export interface ExposureInspectorProjection {
  id: string;
  email: string;
  source: string;
  severity: ExposureSeverity;
  foundAt: string;
  remediation: string;
  monitoringSummary: string;
  relatedOpenFindingCount: number;
}

export interface ActivityFeedItem {
  id: string;
  kind: 'exposure' | 'login' | 'incident';
  date: string;
  title: string;
  detail: string;
  severity: 'warning' | 'caution' | 'neutral';
  needsAttention: boolean;
  actions: ActivityFeedAction[];
}

export interface ActivityFeedAction {
  id: string;
  title: string;
  kind:
    | { type: 'markLoginAsExpected'; loginID: string }
    | { type: 'createIncident'; loginID: string }
    | { type: 'resolveIncident'; incidentID: string };
}

export interface ActivityInspectorProjection {
  id: string;
  title: string;
  categoryLabel: string;
  detail: string;
  occurredAt: string;
  statusText: string;
  severity: 'warning' | 'caution' | 'neutral';
  linkedContext: string | null;
  actions: ActivityFeedAction[];
}

export interface ProviderInspectorProjection {
  providerID: ProviderID;
  providerName: string;
  connectionState: ConnectionState;
  details: string;
}

export interface PendingConfirmationAction {
  title: string;
  message: string;
  confirmTitle: string;
  isDestructive: boolean;
  kind:
    | { type: 'markLoginAsExpected'; loginID: string }
    | { type: 'createIncident'; loginID: string }
    | { type: 'resolveIncident'; incidentID: string };
}

export interface SecurityConsoleError {
  context: string;
  message: string;
  recoverySuggestion: string;
}

export interface OperationFeedback {
  tone: 'success' | 'error' | 'info';
  message: string;
}

interface ProviderLoginSnapshot {
  suspiciousCount: number;
  latestLogin: LoginEvent | null;
}

function isAtRisk(severity: ExposureSeverity): boolean {
  return severity === 'high' || severity === 'critical';
}

function severityRank(severity: ExposureSeverity): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
  }
}

function providerStateRank(state: ConnectionState): number {
  switch (state) {
    case 'error': return 0;
    case 'disconnected': return 1;
    case 'connecting': return 2;
    case 'connected': return 3;
  }
}

export interface SecurityConsoleState {
  exposures: ExposureRecord[];
  loginEvents: LoginEvent[];
  incidents: IncidentCase[];
  providers: ProviderDescriptor[];
  providerStates: Partial<Record<ProviderID, ConnectionState>>;
  riskSnapshot: RiskSnapshot;
  overviewSummary: OverviewSummary;
  overviewRiskDrivers: OverviewRiskDriver[];
  nextAction: NextAction;
  exposureSummary: ExposureSummary;
  exposureFindingRows: ExposureFindingsProjectionRow[];
  overviewSignals: OverviewSignalsProjection;
  sectionBadgeCounts: SectionBadgeCounts;
  overviewActivityPreviewItems: ActivityFeedItem[];
  exposureFilter: ExposureFindingFilter;
  exposureSearchText: string;
  selectedExposureFindingID: string | null;
  scenario: FixtureScenario;
  isRefreshing: boolean;
  lastRefreshAt: string | null;
  presentedError: SecurityConsoleError | null;
  started: boolean;
  filteredExposureFindingRows: ExposureFindingsProjectionRow[];
}

export interface SecurityConsoleActions {
  setExposures: (exposures: ExposureRecord[]) => void;
  setLoginEvents: (loginEvents: LoginEvent[]) => void;
  setIncidents: (incidents: IncidentCase[]) => void;
  setProviders: (providers: ProviderDescriptor[]) => void;
  setProviderStates: (providerStates: Partial<Record<ProviderID, ConnectionState>>) => void;
  setScenario: (scenario: FixtureScenario) => void;
  setRefreshing: (isRefreshing: boolean) => void;
  setLastRefreshAt: (lastRefreshAt: string | null) => void;
  setError: (error: SecurityConsoleError | null) => void;
  setStarted: (started: boolean) => void;
  setExposureFilter: (exposureFilter: ExposureFindingFilter) => void;
  setExposureSearchText: (exposureSearchText: string) => void;
  setSelectedExposureFindingID: (selectedExposureFindingID: string | null) => void;
}

export type SecurityConsoleStore = SecurityConsoleState & SecurityConsoleActions

export const defaultNextAction: NextAction = {
  kind: { type: 'runSecurityCheck' },
  title: 'Run security check',
  detail: 'Start monitoring to discover your security posture.',
  buttonTitle: 'Run check',
  destinationSection: 'overview',
}

export function defaultOverviewSummary(): OverviewSummary {
  return {
    riskScore: 0,
    riskLevel: 'low',
    stateLabel: 'Initializing',
    headline: 'Loading security data...',
    detail: 'Please wait while security data is being loaded.',
    lastUpdatedAt: new Date().toISOString(),
  }
}

function defaultExposureSummary(): ExposureSummary {
  return { openCount: 0, highRiskOpenCount: 0, affectedEmailCount: 0, mostRecentAt: null, headline: 'No data yet', detail: '' };
}

function defaultOverviewSignalsProjection(): OverviewSignalsProjection {
  return { suspiciousSignInCount: 0, openIncidentCount: 0, connectedProviderCount: 0, totalProviderCount: 0 };
}

function defaultSectionBadgeCounts(): SectionBadgeCounts {
  return { activity: 0, exposure: 0, integrations: 0 }
}

export function computeAllProjections(state: Pick<SecurityConsoleState, 'exposures' | 'loginEvents' | 'incidents' | 'providers' | 'providerStates' | 'riskSnapshot'>): Pick<SecurityConsoleState, 'overviewSummary' | 'overviewRiskDrivers' | 'nextAction' | 'exposureSummary' | 'exposureFindingRows' | 'overviewSignals' | 'sectionBadgeCounts' | 'overviewActivityPreviewItems' | 'filteredExposureFindingRows'> {
  const { exposures, loginEvents, incidents, providers, providerStates, riskSnapshot } = state;

  const accountCards = buildAccountCards(providers, loginEvents, providerStates);
  const projectedExposureSummary = buildExposureSummary(exposures);
  const projectedExposureFindingRows = buildExposureFindingRows(exposures);
  const projectedActivityFeed = buildActivityFeed(exposures, loginEvents, incidents);
  const overviewActivityPreviewItems = buildOverviewActivityPreview(projectedActivityFeed);
  const projectedOverviewSignals = buildOverviewSignalsProjection(accountCards, loginEvents, incidents);
  const projectedOverviewSummary = buildOverviewSummary(riskSnapshot, projectedOverviewSignals, projectedExposureSummary);
  const projectedOverviewRiskDrivers = buildOverviewRiskDrivers(projectedOverviewSignals, projectedExposureSummary);
  const projectedNextAction = buildNextAction(exposures, loginEvents, incidents, providers, providerStates);
  const sectionBadgeCounts: SectionBadgeCounts = {
    activity: projectedActivityFeed.filter((i) => i.needsAttention).length,
    exposure: projectedExposureFindingRows.length,
    integrations: accountCards.filter((c) => c.needsAttention).length,
  }

  return {
    overviewSummary: projectedOverviewSummary,
    overviewRiskDrivers: projectedOverviewRiskDrivers,
    nextAction: projectedNextAction,
    exposureSummary: projectedExposureSummary,
    exposureFindingRows: projectedExposureFindingRows,
    overviewSignals: projectedOverviewSignals,
    sectionBadgeCounts,
    overviewActivityPreviewItems,
    filteredExposureFindingRows: projectedExposureFindingRows,
  };
}

function buildOverviewSummary(snapshot: RiskSnapshot, signals: OverviewSignalsProjection, exposureSummary: ExposureSummary): OverviewSummary {
  let stateLabel: string;
  let headline: string;
  switch (snapshot.level) {
    case 'low': stateLabel = 'Stable'; headline = 'No critical risks detected'; break;
    case 'medium': stateLabel = 'Needs attention'; headline = 'Review pending security signals'; break;
    case 'high': stateLabel = 'At risk'; headline = 'Immediate review required'; break;
  }

  const detail = `${exposureSummary.openCount} open exposure alerts · ${signals.suspiciousSignInCount} suspicious sign-ins · ${signals.openIncidentCount} open incidents`;

  return { riskScore: snapshot.score, riskLevel: snapshot.level, stateLabel, headline, detail, lastUpdatedAt: snapshot.lastUpdatedAt };
}

function buildOverviewSignalsProjection(accountCards: AccountCardSummary[], loginEvents: LoginEvent[], incidents: IncidentCase[]): OverviewSignalsProjection {
  return {
    suspiciousSignInCount: loginEvents.filter((l) => l.suspicious || !l.expected).length,
    openIncidentCount: incidents.filter((i) => i.status === 'open').length,
    connectedProviderCount: accountCards.filter((c) => c.connectionState === 'connected').length,
    totalProviderCount: accountCards.length,
  };
}

function buildOverviewRiskDrivers(signals: OverviewSignalsProjection, summary: ExposureSummary): OverviewRiskDriver[] {
  const drivers: OverviewRiskDriver[] = [];
  if (summary.highRiskOpenCount > 0) {
    drivers.push({ id: 'exposures-critical', title: 'High-priority exposures', detail: `${summary.highRiskOpenCount} exposure alert(s) need urgent review.`, emphasis: 'critical' });
  } else if (summary.openCount > 0) {
    drivers.push({ id: 'exposures-open', title: 'Open exposure alerts', detail: `${summary.openCount} exposure alert(s) are still open.`, emphasis: 'caution' });
  }
  if (signals.suspiciousSignInCount > 0) {
    drivers.push({ id: 'signins-suspicious', title: 'Suspicious sign-ins', detail: `${signals.suspiciousSignInCount} sign-in(s) need confirmation.`, emphasis: 'critical' });
  }
  if (signals.openIncidentCount > 0) {
    drivers.push({ id: 'incidents-open', title: 'Open incidents', detail: `${signals.openIncidentCount} incident(s) remain unresolved.`, emphasis: 'caution' });
  }
  if (signals.connectedProviderCount < signals.totalProviderCount) {
    const disconnectedCount = Math.max(0, signals.totalProviderCount - signals.connectedProviderCount);
    drivers.push({ id: 'providers-coverage', title: 'Provider coverage gap', detail: `${disconnectedCount} provider connection(s) are still missing.`, emphasis: 'caution' });
  }
  if (drivers.length === 0) {
    drivers.push({ id: 'healthy-state', title: 'Current coverage looks stable', detail: 'No open exposures, suspicious sign-ins, or connection gaps are driving the score.', emphasis: 'calm' });
  }
  return drivers.slice(0, 3);
}

function buildExposureSummary(exposures: ExposureRecord[]): ExposureSummary {
  const openExposures = exposures.filter((e) => e.status === 'open');
  const highRiskOpenCount = openExposures.filter((e) => isAtRisk(e.severity)).length;
  const affectedEmailCount = new Set(openExposures.map((e) => e.email)).size;
  const mostRecentAt = openExposures.length > 0
    ? openExposures.reduce((a, b) => new Date(a.foundAt).getTime() > new Date(b.foundAt).getTime() ? a : b).foundAt
    : null;
  const headline = openExposures.length === 0 ? 'No open exposure alerts' : highRiskOpenCount > 0 ? 'High-priority exposure alerts found' : 'Exposure alerts need review';
  const detail = openExposures.length === 0
    ? 'Your monitored emails currently have no open exposure findings.'
    : `${openExposures.length} open alert(s) across ${affectedEmailCount} email address(es).`;
  return { openCount: openExposures.length, highRiskOpenCount, affectedEmailCount, mostRecentAt, headline, detail };
}

function buildExposureFindingRows(exposures: ExposureRecord[]): ExposureFindingsProjectionRow[] {
  return exposures
    .filter((e) => e.status === 'open')
    .sort((a, b) => {
      if (severityRank(a.severity) !== severityRank(b.severity)) return severityRank(b.severity) - severityRank(a.severity);
      if (a.foundAt !== b.foundAt) return new Date(b.foundAt).getTime() - new Date(a.foundAt).getTime();
      return a.email.localeCompare(b.email);
    })
    .map((f) => ({
      id: f.id, email: f.email, source: f.source, foundAt: f.foundAt,
      severity: f.severity, remediation: f.remediation,
    }));
}

function buildOverviewActivityPreview(items: ActivityFeedItem[]): ActivityFeedItem[] {
  return [...items]
    .sort((a, b) => {
      if (a.needsAttention !== b.needsAttention) return a.needsAttention ? -1 : 1;
      return new Date(b.date).getTime() - new Date(a.date).getTime();
    })
    .slice(0, 3);
}

export function buildAccountCards(providers: ProviderDescriptor[], loginEvents: LoginEvent[], providerStates: Partial<Record<ProviderID, ConnectionState>>): AccountCardSummary[] {
  const providerLoginSnapshots: Record<string, ProviderLoginSnapshot> = {};
  for (const event of loginEvents) {
    if (!providerLoginSnapshots[event.provider]) providerLoginSnapshots[event.provider] = { suspiciousCount: 0, latestLogin: null };
    const snap = providerLoginSnapshots[event.provider];
    if (event.suspicious || !event.expected) snap.suspiciousCount++;
    if (!snap.latestLogin || new Date(event.occurredAt).getTime() > new Date(snap.latestLogin.occurredAt).getTime()) snap.latestLogin = event;
  }
  return providers
    .map((provider) => {
      const state = providerStates[provider.id] ?? 'disconnected';
      const snap = providerLoginSnapshots[provider.id];
      return {
        providerID: provider.id,
        providerName: provider.displayName,
        details: provider.details,
        connectionState: state,
        suspiciousLoginCount: snap?.suspiciousCount ?? 0,
        latestLoginAt: snap?.latestLogin?.occurredAt ?? null,
        latestLoginSummary: snap?.latestLogin ? `${snap.latestLogin.location} · ${snap.latestLogin.device}` : null,
        needsAttention: state !== 'connected' || (snap?.suspiciousCount ?? 0) > 0,
      };
    })
    .sort((a, b) => {
      if (a.needsAttention !== b.needsAttention) return a.needsAttention ? -1 : 1;
      if (providerStateRank(a.connectionState) !== providerStateRank(b.connectionState)) return providerStateRank(a.connectionState) - providerStateRank(b.connectionState);
      return a.providerName.localeCompare(b.providerName);
    });
}

function buildActivityFeed(exposures: ExposureRecord[], loginEvents: LoginEvent[], incidents: IncidentCase[]): ActivityFeedItem[] {
  const openIncidentLoginIDs = new Set(incidents.filter((i) => i.status === 'open').map((i) => i.linkedLoginEventID));

  const exposureItems = exposures.map((exposure): ActivityFeedItem => ({
    id: `exposure-${exposure.id}`,
    kind: 'exposure' as const,
    date: exposure.foundAt,
    title: `Exposure alert for ${exposure.email}`,
    detail: `${exposure.source} · ${exposure.severity.charAt(0).toUpperCase() + exposure.severity.slice(1)} · ${exposure.status.charAt(0).toUpperCase() + exposure.status.slice(1)}`,
    severity: isAtRisk(exposure.severity) ? 'warning' : exposure.severity === 'medium' ? 'caution' : 'neutral',
    needsAttention: exposure.status === 'open',
    actions: [],
  }));

  const loginItems = loginEvents.map((event): ActivityFeedItem => {
    const needsAttention = event.suspicious || !event.expected;
    const severity: ActivityFeedItem['severity'] = event.suspicious ? 'warning' : needsAttention ? 'caution' : 'neutral';
    const actions: ActivityFeedAction[] = [];
    if (needsAttention) {
      actions.push({ id: `mark-login-${event.id}`, title: 'Mark as me', kind: { type: 'markLoginAsExpected', loginID: event.id } });
      if (!openIncidentLoginIDs.has(event.id)) {
        actions.push({ id: `create-incident-${event.id}`, title: 'Create incident', kind: { type: 'createIncident', loginID: event.id } });
      }
    }
    return { id: `login-${event.id}`, kind: 'login' as const, date: event.occurredAt, title: `${event.provider === 'google' ? 'Google' : event.provider === 'outlook' ? 'Outlook' : 'Other'} sign-in`, detail: `${event.providerAccountEmail ? event.providerAccountEmail + ' · ' : ''}${event.location} · ${event.device} · ${event.reason}`, severity, needsAttention, actions };
  });

  const incidentItems = incidents.map((incident): ActivityFeedItem => {
    const isOpen = incident.status === 'open';
    const actions: ActivityFeedAction[] = isOpen
      ? [{ id: `resolve-incident-${incident.id}`, title: 'Resolve incident', kind: { type: 'resolveIncident', incidentID: incident.id } }]
      : [];
    return { id: `incident-${incident.id}`, kind: 'incident' as const, date: incident.createdAt, title: incident.title, detail: `${incident.severity.charAt(0).toUpperCase() + incident.severity.slice(1)} severity · ${incident.status.charAt(0).toUpperCase() + incident.status.slice(1)}`, severity: isOpen ? 'warning' : 'neutral', needsAttention: isOpen, actions };
  });

  return [...exposureItems, ...loginItems, ...incidentItems].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
}

function buildNextAction(exposures: ExposureRecord[], loginEvents: LoginEvent[], incidents: IncidentCase[], providers: ProviderDescriptor[], providerStates: Partial<Record<ProviderID, ConnectionState>>): NextAction {
  const riskExposure = exposures.filter((e) => e.status === 'open' && isAtRisk(e.severity)).sort((a, b) => new Date(b.foundAt).getTime() - new Date(a.foundAt).getTime())[0];
  if (riskExposure) {
    return { kind: { type: 'reviewHighRiskExposure', exposureID: riskExposure.id }, title: 'Review high-priority exposure', detail: `${riskExposure.email} appears in ${riskExposure.source}.`, buttonTitle: 'Review exposure', destinationSection: 'exposure' };
  }
  const suspicious = loginEvents.filter((l) => l.suspicious || !l.expected).sort((a, b) => new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime())[0];
  if (suspicious) {
    return { kind: { type: 'reviewSuspiciousLogin', loginID: suspicious.id }, title: 'Review suspicious sign-in', detail: `${suspicious.provider === 'google' ? 'Google' : 'Outlook'} sign-in from ${suspicious.location}.`, buttonTitle: 'Review sign-in', destinationSection: 'activity' };
  }
  const openIncident = incidents.filter((i) => i.status === 'open').sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0];
  if (openIncident) {
    return { kind: { type: 'reviewIncident', incidentID: openIncident.id }, title: 'Resolve open incident', detail: openIncident.title, buttonTitle: 'Resolve incident', destinationSection: 'activity' };
  }
  const disconnected = providers.find((provider) => (providerStates[provider.id] ?? 'disconnected') !== 'connected');
  if (disconnected) {
    return { kind: { type: 'connectProvider', providerID: disconnected.id }, title: 'Connect another account', detail: `Add ${disconnected.displayName} to improve monitoring coverage.`, buttonTitle: 'Connect provider', destinationSection: 'integrations' };
  }
  return defaultNextAction;
}

export const createSecurityConsoleStore = (set: any, get: any): SecurityConsoleStore => ({
  exposures: [] as ExposureRecord[],
  loginEvents: [] as LoginEvent[],
  incidents: [] as IncidentCase[],
  providers: [] as ProviderDescriptor[],
  providerStates: {} as Partial<Record<ProviderID, ConnectionState>>,
  riskSnapshot: { score: 0, level: 'low' as RiskLevel, lastUpdatedAt: new Date().toISOString() } as RiskSnapshot,
  overviewSummary: defaultOverviewSummary(),
  overviewRiskDrivers: [] as OverviewRiskDriver[],
  nextAction: defaultNextAction,
  exposureSummary: defaultExposureSummary(),
  exposureFindingRows: [] as ExposureFindingsProjectionRow[],
  overviewSignals: defaultOverviewSignalsProjection(),
  sectionBadgeCounts: defaultSectionBadgeCounts(),
  overviewActivityPreviewItems: [] as ActivityFeedItem[],
  exposureFilter: 'allOpen' as ExposureFindingFilter,
  exposureSearchText: '',
  selectedExposureFindingID: null as string | null,
  scenario: 'moderate' as FixtureScenario,
  isRefreshing: false,
  lastRefreshAt: null as string | null,
  presentedError: null as SecurityConsoleError | null,
  started: false,
  filteredExposureFindingRows: [] as ExposureFindingsProjectionRow[],

  setExposures: (exposures: ExposureRecord[]) => {
    set((state: SecurityConsoleState) => {
      const newState = { ...state, exposures };
      const snapshot = riskScoringEngine.score(newState.exposures, newState.loginEvents, newState.incidents);
      newState.riskSnapshot = snapshot;
      const projections = computeAllProjections({ ...newState, riskSnapshot: snapshot });
      return { ...newState, ...projections };
    });
  },
  setLoginEvents: (loginEvents: LoginEvent[]) => {
    set((state: SecurityConsoleState) => {
      const newState = { ...state, loginEvents };
      const snapshot = riskScoringEngine.score(newState.exposures, newState.loginEvents, newState.incidents);
      newState.riskSnapshot = snapshot;
      const projections = computeAllProjections({ ...newState, riskSnapshot: snapshot });
      return { ...newState, ...projections };
    });
  },
  setIncidents: (incidents: IncidentCase[]) => {
    set((state: SecurityConsoleState) => {
      const newState = { ...state, incidents };
      const snapshot = riskScoringEngine.score(newState.exposures, newState.loginEvents, newState.incidents);
      newState.riskSnapshot = snapshot;
      const projections = computeAllProjections({ ...newState, riskSnapshot: snapshot });
      return { ...newState, ...projections };
    });
  },
  setProviders: (providers: ProviderDescriptor[]) => {
    set((state: SecurityConsoleState) => {
      const projections = computeAllProjections({ ...state, providers })
      return { providers, ...projections }
    })
  },
  setProviderStates: (providerStates: Partial<Record<ProviderID, ConnectionState>>) => {
    set((state: SecurityConsoleState) => {
      const projections = computeAllProjections({ ...state, providerStates })
      return { providerStates, ...projections }
    })
  },
  setScenario: (scenario: FixtureScenario) => set({ scenario }),
  setRefreshing: (isRefreshing: boolean) => set({ isRefreshing }),
  setLastRefreshAt: (lastRefreshAt: string | null) => set({ lastRefreshAt }),
  setError: (error: SecurityConsoleError | null) => set({ presentedError: error }),
  setStarted: (started: boolean) => set({ started }),
  setExposureFilter: (exposureFilter: ExposureFindingFilter) => {
    set((state: SecurityConsoleState) => {
      const filtered = applyExposureFilter(state.exposureFindingRows, exposureFilter, state.exposureSearchText);
      return { exposureFilter, filteredExposureFindingRows: filtered };
    });
  },
  setExposureSearchText: (exposureSearchText: string) => {
    set((state: SecurityConsoleState) => {
      const filtered = applyExposureFilter(state.exposureFindingRows, state.exposureFilter, exposureSearchText);
      return { exposureSearchText, filteredExposureFindingRows: filtered };
    });
  },
  setSelectedExposureFindingID: (selectedExposureFindingID: string | null) => set({ selectedExposureFindingID }),
})

export const useSecurityConsoleStore = create<SecurityConsoleStore>()((set, get) =>
  createSecurityConsoleStore(set, get)
)

function applyExposureFilter(rows: ExposureFindingsProjectionRow[], filter: ExposureFindingFilter, searchText: string): ExposureFindingsProjectionRow[] {
  let scopedRows = filter === 'atRisk' ? rows.filter((r) => isAtRisk(r.severity)) : rows;
  const query = searchText.trim();
  if (!query) return scopedRows;
  return scopedRows.filter((r) => [r.email, r.source, r.remediation].join(' ').toLowerCase().includes(query.toLowerCase()));
}
