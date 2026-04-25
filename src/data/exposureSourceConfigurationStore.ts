import type { ExposureSourceConfiguration } from '@domain/models';
import type { SecureStore } from '@domain/protocols';

const CONFIG_KEY = 'com.secuperso.app.hibp-config';
const LEGACY_EMAIL_KEY = 'com.secuperso.app.hibp-monitored-email';
const MIGRATION_KEY = 'com.secuperso.app.hibp-email-migrated';

export class ExposureSourceConfigurationStore {
  private secureStore: SecureStore;

  constructor(secureStore: SecureStore) {
    this.secureStore = secureStore;
  }

  async loadConfiguration(): Promise<ExposureSourceConfiguration> {
    const raw = await this.secureStore.read(CONFIG_KEY);
    if (!raw) return { apiKey: '', userAgent: 'SecuPersoApp/1.0' };
    try {
      return JSON.parse(raw) as ExposureSourceConfiguration;
    } catch {
      return { apiKey: '', userAgent: 'SecuPersoApp/1.0' };
    }
  }

  async saveConfiguration(config: ExposureSourceConfiguration): Promise<void> {
    await this.secureStore.write(CONFIG_KEY, JSON.stringify(config));
  }

  async migrateLegacyMonitoredEmail(): Promise<string | null> {
    const migrated = await this.secureStore.read(MIGRATION_KEY);
    if (migrated) return null;

    const legacyEmail = await this.secureStore.read(LEGACY_EMAIL_KEY);
    if (!legacyEmail) return null;

    await this.secureStore.write(MIGRATION_KEY, 'true');
    await this.secureStore.delete(LEGACY_EMAIL_KEY);
    return legacyEmail;
  }
}