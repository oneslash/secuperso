import type {
  ExposureRecord,
  LoginEvent,
  ProviderConnection,
  ConnectionState,
} from '@domain/models';
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
  SecureStore,
} from '@domain/protocols';
import { KeychainSecureStore } from './keychainSecureStore';
import { EncryptionKeyProvider } from './encryptionKeyProvider';
import { EncryptedSQLiteDatabase } from './encryptedDatabase';
import { FixtureDataLoader } from './fixtureDataLoader';
import { MockDataCoordinator } from './mockDataCoordinator';
import { MockLoginActivityService, MockIncidentService, MockProviderConnectionService, MockProviderCatalogService, MockScenarioControlService, MockLoginEventActionService } from './mockServices';
import { HaveIBeenPwnedExposureMonitoringService } from './hibpExposureMonitoringService';
import { GoogleWorkspaceLoginActivityService } from './googleWorkspaceLoginActivity';
import { GoogleOAuthService, GoogleOAuthTokenStore } from './auth/googleOAuth';
import { MicrosoftOutlookOAuthService, MicrosoftOAuthTokenStore } from './auth/microsoftOAuth';
import { HybridProviderConnectionService } from './auth/hybridProviderConnectionService';
import { ExposureSourceConfigurationStore } from './exposureSourceConfigurationStore';
import { StreamStore } from './streamStore';

import exposuresJSON from '../../Fixtures/exposures.json';
import loginEventsJSON from '../../Fixtures/login_events.json';
import providersJSON from '../../Fixtures/providers.json';

const IS_MOCK_MODE = true; // DATA_MODE_MOCK

function encrypt(data: object, keyHex: string): Promise<string> {
  const jsonString = JSON.stringify(data);
  return Promise.resolve(btoa(jsonString));
}

function decrypt<T>(payload: string, keyHex: string): Promise<T> {
  const jsonString = atob(payload);
  return Promise.resolve(JSON.parse(jsonString) as T);
}

function emailFingerprint(email: string, keyHex: string): Promise<string> {
  let hash = 0;
  const input = `${email.toLowerCase().trim()}-${keyHex.slice(0, 16)}`;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
  }
  return Promise.resolve(Math.abs(hash).toString(16).padStart(16, '0'));
}

export interface AppServices {
  exposureService: ExposureMonitoringService;
  loginActivityService: LoginActivityService;
  providerConnectionService: ProviderConnectionService;
  incidentService: IncidentService;
  incidentReadableService: IncidentReadableService;
  providerCatalogService: ProviderCatalogService;
  providerConnectionReadableService: ProviderConnectionReadableService;
  scenarioControlService: ScenarioControlService;
  loginEventActionService: LoginEventActionService;
  exposureSourceConfigurationService: ExposureSourceConfigurationService;
  monitoredEmailService: MonitoredEmailService;
  exposureStream: StreamStore<ExposureRecord[]>;
  loginStream: StreamStore<LoginEvent[]>;
}

export async function createAppServices(): Promise<AppServices> {
  const secureStore: SecureStore = new KeychainSecureStore();

  const keyProvider = new EncryptionKeyProvider(secureStore);
  const keyHex = await keyProvider.loadOrCreateKeyData();

  const database = new EncryptedSQLiteDatabase('secuperso');
  await database.initialize();

  const eFn = (data: object) => encrypt(data, keyHex);
  const dFn = <T>(payload: string) => decrypt<T>(payload, keyHex);
  const fpFn = (email: string) => emailFingerprint(email, keyHex);

  const fixtureLoader = new FixtureDataLoader(
    JSON.stringify(exposuresJSON),
    JSON.stringify(loginEventsJSON),
    JSON.stringify(providersJSON),
  );

  const mockCoordinator = new MockDataCoordinator(fixtureLoader, database, eFn, dFn, fpFn);

  const mockLoginService = new MockLoginActivityService(mockCoordinator);
  const mockIncidentService = new MockIncidentService(mockCoordinator);
  const mockProviderConnectionService = new MockProviderConnectionService(mockCoordinator);
  const mockProviderCatalogService = new MockProviderCatalogService(mockCoordinator);
  const mockScenarioControlService = new MockScenarioControlService(mockCoordinator);
  const mockLoginEventActionService = new MockLoginEventActionService(mockCoordinator);

  const googleTokenStore = new GoogleOAuthTokenStore(secureStore);
  const microsoftTokenStore = new MicrosoftOAuthTokenStore(secureStore);

  const googleOAuthService = new GoogleOAuthService(
    {
      clientID: process.env.GOOGLE_OAUTH_CLIENT_ID ?? '',
      redirectURI: process.env.GOOGLE_OAUTH_REDIRECT_URI ?? 'secuperso://oauth',
      scopes: ['openid', 'profile', 'email'],
    },
    googleTokenStore,
  );

  const microsoftOAuthService = new MicrosoftOutlookOAuthService(
    {
      clientID: process.env.MS_ENTRA_CLIENT_ID ?? '',
      tenantID: process.env.MS_ENTRA_TENANT_ID ?? '',
      redirectURI: process.env.MS_ENTRA_REDIRECT_URI ?? 'secuperso://oauth',
      scopes: ['openid', 'profile', 'offline_access', 'User.Read', 'AuditLog.Read.All', 'Directory.Read.All'],
    },
    microsoftTokenStore,
  );

  const hybridProviderService = new HybridProviderConnectionService(
    mockProviderConnectionService,
    googleOAuthService,
    microsoftOAuthService,
  );

  const loginActivityService: LoginActivityService = IS_MOCK_MODE
    ? mockLoginService
    : new GoogleWorkspaceLoginActivityService(googleOAuthService, mockLoginService);

  const exposureService: ExposureMonitoringService & ExposureSourceConfigurationService & MonitoredEmailService =
    new HaveIBeenPwnedExposureMonitoringService(database, secureStore, eFn, dFn, fpFn);

  const exposureStream = new StreamStore<ExposureRecord[]>([]);
  const loginStream = new StreamStore<LoginEvent[]>([]);

  return {
    exposureService: IS_MOCK_MODE ? {
      refresh: async () => {
        const exposures = await mockCoordinator.refreshExposures();
        exposureStream.publish(exposures);
        return exposures;
      },
      stream: (cb) => exposureStream.subscribe(cb),
    } : exposureService,
    loginActivityService,
    providerConnectionService: IS_MOCK_MODE ? mockProviderConnectionService : hybridProviderService,
    incidentService: mockIncidentService,
    incidentReadableService: mockIncidentService,
    providerCatalogService: mockProviderCatalogService,
    providerConnectionReadableService: IS_MOCK_MODE ? mockProviderConnectionService : hybridProviderService,
    scenarioControlService: mockScenarioControlService,
    loginEventActionService: mockLoginEventActionService,
    exposureSourceConfigurationService: IS_MOCK_MODE ? {
      loadConfiguration: async () => ({ apiKey: '', userAgent: 'SecuPersoApp/1.0' }),
      saveConfiguration: async () => {},
    } : exposureService,
    monitoredEmailService: IS_MOCK_MODE ? {
      listMonitoredEmails: async () => [],
      addMonitoredEmail: async () => { throw new Error('Not available in mock mode'); },
      setMonitoredEmailEnabled: async () => {},
      removeMonitoredEmail: async () => {},
    } : exposureService,
    exposureStream,
    loginStream,
  };
}
