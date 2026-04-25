export type ProviderID = 'google' | 'outlook' | 'other';

export const PROVIDER_IDS: ProviderID[] = ['google', 'outlook', 'other'];

export function providerDisplayName(id: ProviderID): string {
  switch (id) {
    case 'google': return 'Google';
    case 'outlook': return 'Outlook';
    case 'other': return 'Other';
  }
}

export type RiskLevel = 'low' | 'medium' | 'high';
export const RISK_LEVELS: RiskLevel[] = ['low', 'medium', 'high'];

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

export type ExposureSeverity = 'low' | 'medium' | 'high' | 'critical';
export const EXPOSURE_SEVERITIES: ExposureSeverity[] = ['low', 'medium', 'high', 'critical'];

export type ExposureStatus = 'open' | 'resolved';
export const EXPOSURE_STATUSES: ExposureStatus[] = ['open', 'resolved'];

export interface ExposureRecord {
  id: string;
  email: string;
  source: string;
  foundAt: string;
  severity: ExposureSeverity;
  status: ExposureStatus;
  remediation: string;
}

export interface MonitoredEmailAddress {
  id: string;
  email: string;
  providerHint: ProviderID;
  isEnabled: boolean;
  createdAt: string;
  lastCheckedAt: string | null;
}

export interface LoginEvent {
  id: string;
  provider: ProviderID;
  providerAccountID?: string;
  providerAccountEmail?: string;
  occurredAt: string;
  device: string;
  ipAddress: string;
  location: string;
  reason: string;
  suspicious: boolean;
  expected: boolean;
}

export type IncidentStatus = 'open' | 'resolved';
export const INCIDENT_STATUSES: IncidentStatus[] = ['open', 'resolved'];

export interface IncidentCase {
  id: string;
  title: string;
  severity: RiskLevel;
  createdAt: string;
  status: IncidentStatus;
  linkedLoginEventID: string;
  notes: string;
  resolvedAt: string | null;
}

export interface RiskSnapshot {
  score: number;
  level: RiskLevel;
  lastUpdatedAt: string;
}

export interface ProviderConnection {
  id: ProviderID;
  state: ConnectionState;
  lastUpdatedAt: string;
}

export interface ProviderConnectionUpdate {
  state: ConnectionState;
  message: string;
}

export interface ProviderDescriptor {
  id: ProviderID;
  displayName: string;
  details: string;
}

export interface ExposureSourceConfiguration {
  apiKey: string;
  userAgent: string;
}

export function isConfigurationComplete(config: ExposureSourceConfiguration): boolean {
  return config.apiKey.trim().length > 0 && config.userAgent.trim().length > 0;
}

export type FixtureScenario = 'clean' | 'moderate' | 'critical';
export const FIXTURE_SCENARIOS: FixtureScenario[] = ['clean', 'moderate', 'critical'];

export function scenarioTitle(scenario: FixtureScenario): string {
  return scenario.charAt(0).toUpperCase() + scenario.slice(1);
}