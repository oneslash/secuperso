import type {
  ExposureRecord,
  LoginEvent,
  ProviderDescriptor,
  ProviderConnection,
  FixtureScenario,
  IncidentCase,
  ProviderID,
  ConnectionState,
} from '@domain/models';
import { providerDisplayName } from '@domain/models';
import { EncryptedSQLiteDatabase } from './encryptedDatabase';
import { FixtureDataLoader } from './fixtureDataLoader';
import { createDataError } from './errors';
import { createLocalID } from './id';

export class MockDataCoordinator {
  private fixtureLoader: FixtureDataLoader;
  private database: EncryptedSQLiteDatabase;
  private encryptFn: (data: object) => Promise<string>;
  private decryptFn: <T>(payload: string) => Promise<T>;
  private emailFingerprintFn: (email: string) => Promise<string>;
  private scenario: FixtureScenario = 'moderate';

  constructor(
    fixtureLoader: FixtureDataLoader,
    database: EncryptedSQLiteDatabase,
    encryptFn: (data: object) => Promise<string>,
    decryptFn: <T>(payload: string) => Promise<T>,
    emailFingerprintFn: (email: string) => Promise<string>,
    initialScenario: FixtureScenario = 'moderate',
  ) {
    this.fixtureLoader = fixtureLoader;
    this.database = database;
    this.encryptFn = encryptFn;
    this.decryptFn = decryptFn;
    this.emailFingerprintFn = emailFingerprintFn;
    this.scenario = initialScenario;
  }

  setScenario(scenario: FixtureScenario): void {
    this.scenario = scenario;
  }

  currentScenario(): FixtureScenario {
    return this.scenario;
  }

  async refreshLoginEvents(): Promise<LoginEvent[]> {
    const events = this.fixtureLoader.loadLoginEvents(this.scenario);
    await this.database.replaceLoginEvents(events, this.encryptFn);
    await this.database.appendAuditEvent(`Refreshed login fixtures for scenario: ${this.scenario}`);
    return this.database.fetchLoginEvents(this.decryptFn);
  }

  async refreshExposures(): Promise<ExposureRecord[]> {
    const exposures = this.fixtureLoader.loadExposures(this.scenario)
    await this.database.replaceExposures(exposures, this.encryptFn)
    await this.database.appendAuditEvent(`Refreshed exposure fixtures for scenario: ${this.scenario}`)
    return this.database.fetchExposures(this.decryptFn)
  }

  async markLoginAsExpected(loginEventID: string): Promise<LoginEvent | null> {
    const loginEvent = await this.database.fetchLoginEvent(loginEventID, this.decryptFn);
    if (!loginEvent) return null;

    const updated: LoginEvent = {
      ...loginEvent,
      expected: true,
      suspicious: false,
      reason: 'Confirmed by user',
    };
    await this.database.upsertLoginEvent(updated, this.encryptFn);
    await this.database.appendAuditEvent(`User marked login event ${loginEventID} as expected`);
    return updated;
  }

  async createIncident(loginEventID: string): Promise<IncidentCase> {
    const login = await this.database.fetchLoginEvent(loginEventID, this.decryptFn);
    if (!login) throw createDataError('loginEventNotFound', loginEventID);

    const incident: IncidentCase = {
      id: createLocalID('incident'),
      title: `Suspicious ${providerDisplayName(login.provider)} sign-in`,
      severity: login.suspicious ? 'high' : 'medium',
      createdAt: new Date().toISOString(),
      status: 'open',
      linkedLoginEventID: login.id,
      notes: 'Auto-generated from login activity.',
      resolvedAt: null,
    };

    await this.database.upsertIncident(incident, this.encryptFn);
    await this.database.appendAuditEvent(`Created incident ${incident.id}`);
    return incident;
  }

  async resolveIncident(incidentID: string): Promise<void> {
    const incident = await this.database.fetchIncident(incidentID, this.decryptFn);
    if (!incident) throw createDataError('incidentNotFound', incidentID);

    const resolved: IncidentCase = {
      ...incident,
      status: 'resolved',
      resolvedAt: new Date().toISOString(),
    };
    await this.database.upsertIncident(resolved, this.encryptFn);
    await this.database.appendAuditEvent(`Resolved incident ${incidentID}`);
  }

  async listIncidents(): Promise<IncidentCase[]> {
    return this.database.fetchIncidents(this.decryptFn);
  }

  async loadProviderCatalog(): Promise<ProviderDescriptor[]> {
    return this.fixtureLoader.loadProviders();
  }

  async updateProviderState(provider: ProviderID, state: ConnectionState): Promise<void> {
    const connection: ProviderConnection = {
      id: provider,
      state,
      lastUpdatedAt: new Date().toISOString(),
    };
    await this.database.upsertProviderConnection(connection, this.encryptFn);
  }

  async listProviderConnections(): Promise<ProviderConnection[]> {
    const connections = await this.database.fetchProviderConnections(this.decryptFn);
    const existingIDs = new Set(connections.map((c) => c.id));
    for (const id of ['google', 'outlook', 'other'] as ProviderID[]) {
      if (!existingIDs.has(id)) {
        const defaultConnection: ProviderConnection = {
          id,
          state: 'disconnected',
          lastUpdatedAt: new Date().toISOString(),
        };
        await this.database.upsertProviderConnection(defaultConnection, this.encryptFn);
      }
    }
    return this.database.fetchProviderConnections(this.decryptFn);
  }
}
