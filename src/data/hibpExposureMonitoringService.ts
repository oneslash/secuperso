import type {
  ExposureRecord,
  ExposureSeverity,
  MonitoredEmailAddress,
  ProviderID,
  ExposureSourceConfiguration,
  ExposureStatus,
} from '@domain/models';
import type { ExposureMonitoringService, ExposureSourceConfigurationService, MonitoredEmailService, SecureStore } from '@domain/protocols';
import { createDataError } from './errors';
import { EncryptedSQLiteDatabase } from './encryptedDatabase';
import { StreamStore } from './streamStore';
import { createLocalID } from './id';

const HIBP_BASE_URL = 'https://haveibeenpwned.com/api/v3';
const REQUEST_INTERVAL_MS = 2000;

const CRITICAL_DATA_CLASSES = new Set([
  'Passwords', 'SSN', 'Social Security Numbers', 'Credit cards', 'Bank account numbers',
]);

const HIGH_RISK_DATA_CLASSES = new Set([
  'Email addresses', 'Phone numbers', 'Dates of birth', 'Physical addresses',
  'IP addresses', 'Geographic locations',
]);

interface HIBPBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  Description: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
  IsMalware: boolean;
  IsStealerLog: boolean;
  PwnCount: number;
  LogoPath: string;
}

function classifySeverity(breach: HIBPBreach): ExposureSeverity {
  const dataClasses = breach.DataClasses ?? [];
  if (dataClasses.some((dc) => CRITICAL_DATA_CLASSES.has(dc))) return 'critical';
  if (breach.PwnCount >= 10_000_000) return 'high';
  if (breach.IsSensitive || breach.IsStealerLog || breach.IsMalware) return 'high';
  if (dataClasses.some((dc) => HIGH_RISK_DATA_CLASSES.has(dc))) return 'high';
  if (dataClasses.length >= 5) return 'medium';
  return 'low';
}

function generateRemediation(breach: HIBPBreach): string {
  const dataClasses = breach.DataClasses ?? [];
  if (dataClasses.some((dc) => CRITICAL_DATA_CLASSES.has(dc))) {
    return `Immediately change your password for ${breach.Domain || breach.Title} and enable 2FA where possible. Review financial accounts.`;
  }
  if (breach.IsStealerLog) {
    return `Your credentials were captured by malware. Rotate all passwords used on similar sites and check for unauthorized sessions.`;
  }
  if (breach.IsMalware) {
    return `Data was harvested by malware. Scan your devices and rotate passwords for affected accounts.`;
  }
  return `Update your password for ${breach.Domain || breach.Title} and review your security settings.`;
}

function generateDeterministicID(email: string, breachName: string, breachDate: string): string {
  const raw = `exposure-${email}-${breachName}-${breachDate}`;
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = ((hash << 5) - hash + raw.charCodeAt(i)) | 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8 % 8, (8 % 8) + 4)}-${hex.slice(0, 4)}-a000-000000000000`;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export class HaveIBeenPwnedExposureMonitoringService implements ExposureMonitoringService, ExposureSourceConfigurationService, MonitoredEmailService {
  private apiKey: string = '';
  private userAgent: string = 'SecuPersoApp/1.0';
  private database: EncryptedSQLiteDatabase;
  private encryptFn: (data: object) => Promise<string>;
  private decryptFn: <T>(payload: string) => Promise<T>;
  private emailFingerprintFn: (email: string) => Promise<string>;
  private secureStore: SecureStore;
  private configKey = 'com.secuperso.app.hibp-config';
  private legacyEmailKey = 'com.secuperso.app.hibp-monitored-email';
  private migrationKey = 'com.secuperso.app.hibp-email-migrated';
  private exposureStream = new StreamStore<ExposureRecord[]>([]);
  private loginStream = new StreamStore<ExposureRecord[]>([]);
  private rateLimitLastRequest = 0;

  constructor(
    database: EncryptedSQLiteDatabase,
    secureStore: SecureStore,
    encryptFn: (data: object) => Promise<string>,
    decryptFn: <T>(payload: string) => Promise<T>,
    emailFingerprintFn: (email: string) => Promise<string>,
  ) {
    this.database = database;
    this.secureStore = secureStore;
    this.encryptFn = encryptFn;
    this.decryptFn = decryptFn;
    this.emailFingerprintFn = emailFingerprintFn;
  }

  async refresh(): Promise<ExposureRecord[]> {
    const config = await this.loadConfiguration();
    if (!config.apiKey.trim()) {
      const existing = await this.database.fetchExposures(this.decryptFn);
      this.exposureStream.publish(existing);
      return existing;
    }

    this.apiKey = config.apiKey;
    this.userAgent = config.userAgent || 'SecuPersoApp/1.0';

    const monitoredEmails = await this.listMonitoredEmails();
    const activeEmails = monitoredEmails.filter((e) => e.isEnabled);
    const allBreaches: ExposureRecord[] = [];

    for (const emailEntry of activeEmails) {
      await this.enforceRateLimit();
      try {
        const breaches = await this.fetchBreachesForEmail(emailEntry.email);
        for (const breach of breaches) {
          allBreaches.push({
            id: generateDeterministicID(emailEntry.email, breach.Name, breach.BreachDate),
            email: emailEntry.email,
            source: breach.Title || breach.Name,
            foundAt: breach.BreachDate,
            severity: classifySeverity(breach),
            status: 'open' as ExposureStatus,
            remediation: generateRemediation(breach),
          });
        }
      } catch (e: any) {
        // Continue with other emails if one fails
      }
    }

    await this.database.replaceExposures(allBreaches, this.encryptFn);
    this.exposureStream.publish(allBreaches);
    return allBreaches;
  }

  stream(callback: (values: ExposureRecord[]) => void): () => void {
    return this.exposureStream.subscribe(callback);
  }

  async loadConfiguration(): Promise<ExposureSourceConfiguration> {
    const raw = await this.secureStore.read(this.configKey);
    if (!raw) return { apiKey: '', userAgent: 'SecuPersoApp/1.0' };
    try {
      return JSON.parse(raw) as ExposureSourceConfiguration;
    } catch {
      return { apiKey: '', userAgent: 'SecuPersoApp/1.0' };
    }
  }

  async saveConfiguration(config: ExposureSourceConfiguration): Promise<void> {
    await this.secureStore.write(this.configKey, JSON.stringify(config));
    this.apiKey = config.apiKey;
    this.userAgent = config.userAgent;
  }

  async listMonitoredEmails(): Promise<MonitoredEmailAddress[]> {
    return this.database.fetchMonitoredEmails(this.decryptFn);
  }

  async addMonitoredEmail(email: string, providerHint: ProviderID): Promise<MonitoredEmailAddress> {
    const normalized = normalizeEmail(email);
    if (!isValidEmail(normalized)) {
      throw createDataError('invalidRemoteConfiguration', 'Invalid email address');
    }

    const entry: MonitoredEmailAddress = {
      id: createLocalID('email'),
      email: normalized,
      providerHint,
      isEnabled: true,
      createdAt: new Date().toISOString(),
      lastCheckedAt: null,
    };

    const fingerprint = await this.emailFingerprintFn(normalized);
    await this.database.upsertMonitoredEmail(entry, this.encryptFn, fingerprint);
    return entry;
  }

  async setMonitoredEmailEnabled(id: string, isEnabled: boolean): Promise<void> {
    const existing = await this.database.fetchMonitoredEmail(id, this.decryptFn);
    if (!existing) throw createDataError('monitoredEmailNotFound', id);
    const updated = { ...existing, isEnabled };
    const fingerprint = await this.emailFingerprintFn(updated.email);
    await this.database.upsertMonitoredEmail(updated, this.encryptFn, fingerprint);
  }

  async removeMonitoredEmail(id: string): Promise<void> {
    await this.database.removeMonitoredEmail(id);
  }

  private async fetchBreachesForEmail(email: string): Promise<HIBPBreach[]> {
    const response = await fetch(`${HIBP_BASE_URL}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: {
        'hibp-api-key': this.apiKey,
        'user-agent': this.userAgent,
      },
    });

    if (response.status === 404) return [];
    if (response.status === 401) throw createDataError('remoteRequestRejected', 401, 'HIBP API key invalid');
    if (response.status === 429) throw createDataError('remoteRequestRejected', 429, 'HIBP rate limit exceeded');
    if (!response.ok) throw createDataError('remoteRequestRejected', response.status, 'HIBP request failed');

    return response.json();
  }

  private async enforceRateLimit(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.rateLimitLastRequest;
    if (elapsed < REQUEST_INTERVAL_MS) {
      await new Promise((resolve) => setTimeout(resolve, REQUEST_INTERVAL_MS - elapsed));
    }
    this.rateLimitLastRequest = Date.now();
  }
}
