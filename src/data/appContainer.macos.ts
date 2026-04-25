import type {
  ExposureRecord,
  LoginEvent,
  ProviderConnection,
  ProviderDescriptor,
  ConnectionState,
  FixtureScenario,
  MonitoredEmailAddress,
  ExposureSourceConfiguration,
  ProviderID,
  IncidentCase,
} from '@domain/models'
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
  ExposureSourceConfigurationService,
  MonitoredEmailService,
} from '@domain/protocols'
import { FixtureDataLoader } from './fixtureDataLoader'
import {
  MockIncidentService,
  MockLoginActivityService,
  MockLoginEventActionService,
  MockProviderCatalogService,
  MockProviderConnectionService,
  MockScenarioControlService,
} from './mockServices'
import { StreamStore } from './streamStore'
import { createDataError } from './errors'
import { createLocalID } from './id'

import exposuresJSON from '../../Fixtures/exposures.json'
import loginEventsJSON from '../../Fixtures/login_events.json'
import providersJSON from '../../Fixtures/providers.json'

class DesktopMockCoordinator {
  private fixtureLoader: FixtureDataLoader
  private scenario: FixtureScenario
  private exposures: ExposureRecord[] = []
  private loginEvents: LoginEvent[] = []
  private incidents: IncidentCase[] = []
  private providers: ProviderDescriptor[] = []
  private providerConnections: Record<ProviderID, ProviderConnection> = {
    google: { id: 'google', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
    outlook: { id: 'outlook', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
    other: { id: 'other', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
  }

  constructor(fixtureLoader: FixtureDataLoader, initialScenario: FixtureScenario = 'moderate') {
    this.fixtureLoader = fixtureLoader
    this.scenario = initialScenario
    this.providers = this.fixtureLoader.loadProviders()
    this.loadScenarioData(initialScenario)
  }

  private loadScenarioData(scenario: FixtureScenario): void {
    this.exposures = [...this.fixtureLoader.loadExposures(scenario)]
    this.loginEvents = [...this.fixtureLoader.loadLoginEvents(scenario)]
    this.incidents = []
    this.providerConnections = {
      google: { id: 'google', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
      outlook: { id: 'outlook', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
      other: { id: 'other', state: 'disconnected', lastUpdatedAt: new Date().toISOString() },
    }
  }

  setScenario(scenario: FixtureScenario): void {
    this.scenario = scenario
    this.loadScenarioData(scenario)
  }

  currentScenario(): FixtureScenario {
    return this.scenario
  }

  async refreshExposures(): Promise<ExposureRecord[]> {
    this.exposures = [...this.fixtureLoader.loadExposures(this.scenario)]
    return this.exposures
  }

  async refreshLoginEvents(): Promise<LoginEvent[]> {
    this.loginEvents = [...this.fixtureLoader.loadLoginEvents(this.scenario)]
    return this.loginEvents
  }

  async markLoginAsExpected(loginEventID: string): Promise<LoginEvent | null> {
    const match = this.loginEvents.find((event) => event.id === loginEventID)
    if (!match) {
      return null
    }

    const updated = {
      ...match,
      expected: true,
      suspicious: false,
      reason: 'Confirmed by user',
    }

    this.loginEvents = this.loginEvents.map((event) => (
      event.id === loginEventID ? updated : event
    ))

    return updated
  }

  async createIncident(loginEventID: string): Promise<IncidentCase> {
    const login = this.loginEvents.find((event) => event.id === loginEventID)
    if (!login) {
      throw createDataError('loginEventNotFound', loginEventID)
    }

    const incident: IncidentCase = {
      id: createLocalID('incident'),
      title: `Suspicious ${login.provider === 'google' ? 'Google' : login.provider === 'outlook' ? 'Outlook' : 'provider'} sign-in`,
      severity: login.suspicious ? 'high' : 'medium',
      createdAt: new Date().toISOString(),
      status: 'open',
      linkedLoginEventID: loginEventID,
      notes: 'Auto-generated from desktop mock activity.',
      resolvedAt: null,
    }

    this.incidents = [incident, ...this.incidents]
    return incident
  }

  async resolveIncident(incidentID: string): Promise<void> {
    this.incidents = this.incidents.map((incident) => (
      incident.id === incidentID
        ? { ...incident, status: 'resolved', resolvedAt: new Date().toISOString() }
        : incident
    ))
  }

  async listIncidents(): Promise<IncidentCase[]> {
    return [...this.incidents].sort(
      (left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()
    )
  }

  async loadProviderCatalog(): Promise<ProviderDescriptor[]> {
    return this.providers
  }

  async updateProviderState(provider: ProviderID, state: ConnectionState): Promise<void> {
    this.providerConnections[provider] = {
      id: provider,
      state,
      lastUpdatedAt: new Date().toISOString(),
    }
  }

  async listProviderConnections(): Promise<ProviderConnection[]> {
    return Object.values(this.providerConnections).sort((left, right) => left.id.localeCompare(right.id))
  }
}

export interface AppServices {
  exposureService: ExposureMonitoringService
  loginActivityService: LoginActivityService
  providerConnectionService: ProviderConnectionService
  incidentService: IncidentService
  incidentReadableService: IncidentReadableService
  providerCatalogService: ProviderCatalogService
  providerConnectionReadableService: ProviderConnectionReadableService
  scenarioControlService: ScenarioControlService
  loginEventActionService: LoginEventActionService
  exposureSourceConfigurationService: ExposureSourceConfigurationService
  monitoredEmailService: MonitoredEmailService
  exposureStream: StreamStore<ExposureRecord[]>
  loginStream: StreamStore<LoginEvent[]>
}

export async function createAppServices(): Promise<AppServices> {
  const fixtureLoader = new FixtureDataLoader(
    JSON.stringify(exposuresJSON),
    JSON.stringify(loginEventsJSON),
    JSON.stringify(providersJSON)
  )

  const coordinator = new DesktopMockCoordinator(fixtureLoader)
  const exposureStream = new StreamStore<ExposureRecord[]>([])
  const loginStream = new StreamStore<LoginEvent[]>([])

  const exposureService: ExposureMonitoringService = {
    refresh: async () => {
      const exposures = await coordinator.refreshExposures()
      exposureStream.publish(exposures)
      return exposures
    },
    stream: (callback) => exposureStream.subscribe(callback),
  }

  const loginActivityService: LoginActivityService = {
    refresh: async () => {
      const events = await coordinator.refreshLoginEvents()
      loginStream.publish(events)
      return events
    },
    stream: (callback) => loginStream.subscribe(callback),
  }

  const providerConnectionService = new MockProviderConnectionService(coordinator as any)
  const incidentService = new MockIncidentService(coordinator as any)
  const providerCatalogService = new MockProviderCatalogService(coordinator as any)
  const scenarioControlService = new MockScenarioControlService(coordinator as any)
  const loginEventActionService = new MockLoginEventActionService(coordinator as any)

  let configuration: ExposureSourceConfiguration = {
    apiKey: '',
    userAgent: 'SecuPersoDesktop/1.0',
  }
  let monitoredEmails: MonitoredEmailAddress[] = []

  const exposureSourceConfigurationService: ExposureSourceConfigurationService = {
    loadConfiguration: async () => configuration,
    saveConfiguration: async (nextConfiguration) => {
      configuration = nextConfiguration
    },
  }

  const monitoredEmailService: MonitoredEmailService = {
    listMonitoredEmails: async () => monitoredEmails,
    addMonitoredEmail: async (email, providerHint) => {
      const entry: MonitoredEmailAddress = {
        id: createLocalID('email'),
        email: email.trim().toLowerCase(),
        providerHint,
        isEnabled: true,
        createdAt: new Date().toISOString(),
        lastCheckedAt: null,
      }
      monitoredEmails = [...monitoredEmails, entry]
      return entry
    },
    setMonitoredEmailEnabled: async (id, isEnabled) => {
      monitoredEmails = monitoredEmails.map((entry) => (
        entry.id === id ? { ...entry, isEnabled } : entry
      ))
    },
    removeMonitoredEmail: async (id) => {
      monitoredEmails = monitoredEmails.filter((entry) => entry.id !== id)
    },
  }

  return {
    exposureService,
    loginActivityService,
    providerConnectionService,
    incidentService,
    incidentReadableService: incidentService,
    providerCatalogService,
    providerConnectionReadableService: providerConnectionService,
    scenarioControlService,
    loginEventActionService,
    exposureSourceConfigurationService,
    monitoredEmailService,
    exposureStream,
    loginStream,
  }
}
