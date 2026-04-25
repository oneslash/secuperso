import type {
  ExposureRecord,
  LoginEvent,
  ProviderID,
  ProviderConnection,
  ProviderConnectionUpdate,
  ProviderDescriptor,
  IncidentCase,
  FixtureScenario,
  MonitoredEmailAddress,
} from '@domain/models';
import { PROVIDER_IDS, providerDisplayName } from '@domain/models';
import type {
  ExposureMonitoringService,
  LoginActivityService,
  ProviderConnectionService,
  IncidentService,
  IncidentReadableService,
  ProviderCatalogService,
  ProviderConnectionReadableService,
  ScenarioControlService,
  LoginEventActionService,
  MonitoredEmailService,
  ExposureSourceConfigurationService,
} from '@domain/protocols';
import { StreamStore } from './streamStore';

export class MockLoginActivityService implements LoginActivityService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;
  private streamStore = new StreamStore<LoginEvent[]>([]);

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async refresh(): Promise<LoginEvent[]> {
    const events = await this.coordinator.refreshLoginEvents();
    this.streamStore.publish(events);
    return events;
  }

  stream(callback: (values: LoginEvent[]) => void): () => void {
    return this.streamStore.subscribe(callback);
  }
}

export class MockIncidentService implements IncidentService, IncidentReadableService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async create(loginEventID: string): Promise<IncidentCase> {
    return this.coordinator.createIncident(loginEventID);
  }

  async resolve(incidentID: string): Promise<void> {
    return this.coordinator.resolveIncident(incidentID);
  }

  async list(): Promise<IncidentCase[]> {
    return this.coordinator.listIncidents();
  }
}

export class MockProviderConnectionService implements ProviderConnectionService, ProviderConnectionReadableService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async beginConnection(provider: ProviderID, onUpdate: (update: ProviderConnectionUpdate) => void): Promise<() => void> {
    const cancelled = { value: false };

    const run = async () => {
      onUpdate({ state: 'connecting', message: 'Opening consent screen...' });
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (cancelled.value) return;

      onUpdate({ state: 'connecting', message: 'Granting permissions...' });
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (cancelled.value) return;

      const finalState = provider === 'other' ? 'error' : 'connected';
      await this.coordinator.updateProviderState(provider, finalState);
      const finalMessage = finalState === 'connected'
        ? 'Provider connected successfully.'
        : 'Provider connection failed in mock flow.';
      onUpdate({ state: finalState, message: finalMessage });
    };

    run();
    return () => { cancelled.value = true; };
  }

  async disconnect(provider: ProviderID): Promise<void> {
    return this.coordinator.updateProviderState(provider, 'disconnected');
  }

  async connections(): Promise<ProviderConnection[]> {
    return this.coordinator.listProviderConnections();
  }
}

export class MockProviderCatalogService implements ProviderCatalogService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async providers(): Promise<ProviderDescriptor[]> {
    return this.coordinator.loadProviderCatalog();
  }
}

export class MockScenarioControlService implements ScenarioControlService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async setScenario(scenario: FixtureScenario): Promise<void> {
    this.coordinator.setScenario(scenario);
  }

  async currentScenario(): Promise<FixtureScenario> {
    return this.coordinator.currentScenario();
  }
}

export class MockLoginEventActionService implements LoginEventActionService {
  private coordinator: import('./mockDataCoordinator').MockDataCoordinator;

  constructor(coordinator: import('./mockDataCoordinator').MockDataCoordinator) {
    this.coordinator = coordinator;
  }

  async markAsExpected(loginEventID: string): Promise<LoginEvent | null> {
    return this.coordinator.markLoginAsExpected(loginEventID);
  }
}