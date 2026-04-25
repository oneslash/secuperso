import type {
  ExposureRecord,
  LoginEvent,
  ProviderID,
  ProviderConnectionUpdate,
  ProviderConnection,
  IncidentCase,
  ProviderDescriptor,
  FixtureScenario,
  ExposureSourceConfiguration,
  MonitoredEmailAddress,
} from './models';

export interface ExposureMonitoringService {
  refresh(): Promise<ExposureRecord[]>;
  stream(callback: (values: ExposureRecord[]) => void): () => void;
}

export interface LoginActivityService {
  refresh(): Promise<LoginEvent[]>;
  stream(callback: (values: LoginEvent[]) => void): () => void;
}

export interface ProviderConnectionService {
  beginConnection(provider: ProviderID, onUpdate: (update: ProviderConnectionUpdate) => void): Promise<() => void>;
  disconnect(provider: ProviderID): Promise<void>;
}

export interface IncidentService {
  create(loginEventID: string): Promise<IncidentCase>;
  resolve(incidentID: string): Promise<void>;
}

export interface SecureStore {
  read(key: string): Promise<string | null>;
  write(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface IncidentReadableService {
  list(): Promise<IncidentCase[]>;
}

export interface ProviderCatalogService {
  providers(): Promise<ProviderDescriptor[]>;
}

export interface ProviderConnectionReadableService {
  connections(): Promise<ProviderConnection[]>;
}

export interface ScenarioControlService {
  setScenario(scenario: FixtureScenario): Promise<void>;
  currentScenario(): Promise<FixtureScenario>;
}

export interface LoginEventActionService {
  markAsExpected(loginEventID: string): Promise<LoginEvent | null>;
}

export interface ExposureSourceConfigurationService {
  loadConfiguration(): Promise<ExposureSourceConfiguration>;
  saveConfiguration(config: ExposureSourceConfiguration): Promise<void>;
}

export interface MonitoredEmailService {
  listMonitoredEmails(): Promise<MonitoredEmailAddress[]>;
  addMonitoredEmail(email: string, providerHint: ProviderID): Promise<MonitoredEmailAddress>;
  setMonitoredEmailEnabled(id: string, isEnabled: boolean): Promise<void>;
  removeMonitoredEmail(id: string): Promise<void>;
}