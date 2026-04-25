import { open, type DB, type QueryResult } from '@op-engineering/op-sqlite';
import type { ExposureRecord, MonitoredEmailAddress, LoginEvent, IncidentCase, ProviderConnection } from '@domain/models';
import { createDataError } from './errors';
import type { SecuPersoDataError } from './errors';

interface PayloadRow {
  id: string;
  updatedAt: number;
  payload: string;
}

export class EncryptedSQLiteDatabase {
  private db: DB;
  private initialized = false;

  constructor(dbName: string = 'secuperso') {
    this.db = open({ name: dbName });
  }

  private executeSql(query: string, params?: Array<string | number | boolean | null>): Promise<QueryResult> {
    return this.db.execute(query, params)
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS exposures (
        id TEXT PRIMARY KEY NOT NULL,
        scope_fingerprint TEXT NOT NULL DEFAULT '',
        updated_at REAL NOT NULL,
        payload TEXT NOT NULL
      );
    `);

    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_exposures_updated_at ON exposures(updated_at);`);
    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_exposures_scope_fingerprint ON exposures(scope_fingerprint);`);

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS monitored_emails (
        id TEXT PRIMARY KEY NOT NULL,
        email_fingerprint TEXT NOT NULL UNIQUE,
        updated_at REAL NOT NULL,
        payload TEXT NOT NULL
      );
    `);
    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_monitored_emails_updated_at ON monitored_emails(updated_at);`);

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS login_events (
        id TEXT PRIMARY KEY NOT NULL,
        updated_at REAL NOT NULL,
        payload TEXT NOT NULL
      );
    `);
    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_login_events_updated_at ON login_events(updated_at);`);

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY NOT NULL,
        updated_at REAL NOT NULL,
        payload TEXT NOT NULL
      );
    `);
    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);`);

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS provider_connections (
        id TEXT PRIMARY KEY NOT NULL,
        updated_at REAL NOT NULL,
        payload TEXT NOT NULL
      );
    `);
    await this.executeSql(`CREATE INDEX IF NOT EXISTS idx_provider_connections_updated_at ON provider_connections(updated_at);`);

    await this.executeSql(`
      CREATE TABLE IF NOT EXISTS app_audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at REAL NOT NULL,
        event TEXT NOT NULL
      );
    `);

    this.initialized = true;
  }

  async replaceExposures(exposures: ExposureRecord[], encryptFn: (data: object) => Promise<string>): Promise<void> {
    await this.executeSql('BEGIN TRANSACTION');
    try {
      await this.executeSql('DELETE FROM exposures');
      for (const record of exposures) {
        const payload = await encryptFn(record);
        const scopeFingerprint = ''; // Will be computed externally
        await this.executeSql(
          `INSERT INTO exposures (id, scope_fingerprint, updated_at, payload) VALUES (?, ?, ?, ?)`,
          [record.id, scopeFingerprint, new Date(record.foundAt).getTime() / 1000, payload]
        );
      }
      await this.executeSql('COMMIT');
    } catch (e) {
      await this.executeSql('ROLLBACK');
      throw e;
    }
  }

  async replaceExposuresForScope(scopeFingerprint: string, records: ExposureRecord[], encryptFn: (data: object) => Promise<string>): Promise<void> {
    await this.executeSql('BEGIN TRANSACTION');
    try {
      await this.executeSql('DELETE FROM exposures WHERE scope_fingerprint = ?', [scopeFingerprint]);
      for (const record of records) {
        const payload = await encryptFn(record);
        await this.executeSql(
          `INSERT INTO exposures (id, scope_fingerprint, updated_at, payload) VALUES (?, ?, ?, ?)`,
          [record.id, scopeFingerprint, new Date(record.foundAt).getTime() / 1000, payload]
        );
      }
      await this.executeSql('COMMIT');
    } catch (e) {
      await this.executeSql('ROLLBACK');
      throw e;
    }
  }

  async fetchExposures(decryptFn: (payload: string) => Promise<ExposureRecord>): Promise<ExposureRecord[]> {
    const rows = await this.fetchPayloadRows('exposures');
    const results = await Promise.all(rows.map((r) => decryptFn(r.payload)));
    return results.sort((a, b) => new Date(b.foundAt).getTime() - new Date(a.foundAt).getTime());
  }

  async upsertMonitoredEmail(email: MonitoredEmailAddress, encryptFn: (data: object) => Promise<string>, fingerprint: string): Promise<void> {
    const payload = await encryptFn(email);
    try {
      await this.executeSql(
        `INSERT INTO monitored_emails (id, email_fingerprint, updated_at, payload)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET email_fingerprint = excluded.email_fingerprint, updated_at = excluded.updated_at, payload = excluded.payload;`,
        [email.id, fingerprint, new Date(email.lastCheckedAt ?? email.createdAt).getTime() / 1000, payload]
      );
    } catch (e: any) {
      if (e.message?.includes('UNIQUE constraint failed: monitored_emails.email_fingerprint')) {
        throw createDataError('duplicateMonitoredEmail');
      }
      throw e;
    }
  }

  async fetchMonitoredEmails(decryptFn: (payload: string) => Promise<MonitoredEmailAddress>): Promise<MonitoredEmailAddress[]> {
    const rows = await this.fetchPayloadRows('monitored_emails');
    const results = await Promise.all(rows.map((r) => decryptFn(r.payload)));
    return results.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  }

  async fetchMonitoredEmail(id: string, decryptFn: (payload: string) => Promise<MonitoredEmailAddress>): Promise<MonitoredEmailAddress | null> {
    const row = await this.fetchPayloadRow('monitored_emails', id);
    if (!row) return null;
    return decryptFn(row.payload);
  }

  async removeMonitoredEmail(id: string): Promise<void> {
    await this.executeSql('BEGIN TRANSACTION');
    try {
      const fingerprintRow = await this.executeSql(
        'SELECT email_fingerprint FROM monitored_emails WHERE id = ? LIMIT 1;',
        [id]
      );
      if (fingerprintRow.rows.length === 0) {
        throw createDataError('monitoredEmailNotFound', id);
      }
      const fingerprint = fingerprintRow.rows[0].email_fingerprint as string;

      await this.executeSql('DELETE FROM monitored_emails WHERE id = ?', [id]);
      await this.executeSql('DELETE FROM exposures WHERE scope_fingerprint = ?', [fingerprint]);
      await this.executeSql('COMMIT');
    } catch (e) {
      await this.executeSql('ROLLBACK');
      throw e;
    }
  }

  async replaceLoginEvents(events: LoginEvent[], encryptFn: (data: object) => Promise<string>): Promise<void> {
    await this.executeSql('BEGIN TRANSACTION');
    try {
      await this.executeSql('DELETE FROM login_events');
      for (const event of events) {
        const payload = await encryptFn(event);
        await this.executeSql(
          `INSERT INTO login_events (id, updated_at, payload) VALUES (?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload;`,
          [event.id, new Date(event.occurredAt).getTime() / 1000, payload]
        );
      }
      await this.executeSql('COMMIT');
    } catch (e) {
      await this.executeSql('ROLLBACK');
      throw e;
    }
  }

  async upsertLoginEvent(event: LoginEvent, encryptFn: (data: object) => Promise<string>): Promise<void> {
    const payload = await encryptFn(event);
    await this.executeSql(
      `INSERT INTO login_events (id, updated_at, payload) VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload;`,
      [event.id, new Date(event.occurredAt).getTime() / 1000, payload]
    );
  }

  async fetchLoginEvents(decryptFn: (payload: string) => Promise<LoginEvent>): Promise<LoginEvent[]> {
    const rows = await this.fetchPayloadRows('login_events');
    const results = await Promise.all(rows.map((r) => decryptFn(r.payload)));
    return results.sort((a, b) => new Date(b.occurredAt).getTime() - new Date(a.occurredAt).getTime());
  }

  async fetchLoginEvent(id: string, decryptFn: (payload: string) => Promise<LoginEvent>): Promise<LoginEvent | null> {
    const row = await this.fetchPayloadRow('login_events', id);
    if (!row) return null;
    return decryptFn(row.payload);
  }

  async upsertIncident(incident: IncidentCase, encryptFn: (data: object) => Promise<string>): Promise<void> {
    const payload = await encryptFn(incident);
    await this.executeSql(
      `INSERT INTO incidents (id, updated_at, payload) VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload;`,
      [incident.id, new Date(incident.createdAt).getTime() / 1000, payload]
    );
  }

  async fetchIncident(id: string, decryptFn: (payload: string) => Promise<IncidentCase>): Promise<IncidentCase | null> {
    const row = await this.fetchPayloadRow('incidents', id);
    if (!row) return null;
    return decryptFn(row.payload);
  }

  async fetchIncidents(decryptFn: (payload: string) => Promise<IncidentCase>): Promise<IncidentCase[]> {
    const rows = await this.fetchPayloadRows('incidents');
    const results = await Promise.all(rows.map((r) => decryptFn(r.payload)));
    return results.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  async upsertProviderConnection(connection: ProviderConnection, encryptFn: (data: object) => Promise<string>): Promise<void> {
    const payload = await encryptFn(connection);
    await this.executeSql(
      `INSERT INTO provider_connections (id, updated_at, payload) VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload;`,
      [connection.id, new Date(connection.lastUpdatedAt).getTime() / 1000, payload]
    );
  }

  async fetchProviderConnections(decryptFn: (payload: string) => Promise<ProviderConnection>): Promise<ProviderConnection[]> {
    const rows = await this.fetchPayloadRows('provider_connections');
    const results = await Promise.all(rows.map((r) => decryptFn(r.payload)));
    return results.sort((a, b) => a.id.localeCompare(b.id));
  }

  async appendAuditEvent(event: string, createdAt: Date = new Date()): Promise<void> {
    await this.executeSql(
      'INSERT INTO app_audit_events (created_at, event) VALUES (?, ?);',
      [createdAt.getTime() / 1000, event]
    );
  }

  private async fetchPayloadRows(table: string): Promise<PayloadRow[]> {
    const result = await this.executeSql(
      `SELECT id, updated_at AS updatedAt, payload FROM ${table} ORDER BY updated_at DESC;`
    )
    return result.rows.map((row) => ({
      id: String(row.id),
      updatedAt: Number(row.updatedAt ?? 0),
      payload: String(row.payload ?? ''),
    }))
  }

  private async fetchPayloadRow(table: string, id: string): Promise<PayloadRow | null> {
    const result = await this.executeSql(
      `SELECT id, updated_at AS updatedAt, payload FROM ${table} WHERE id = ? LIMIT 1;`,
      [id]
    )
    const rows = result.rows.map((row) => ({
      id: String(row.id),
      updatedAt: Number(row.updatedAt ?? 0),
      payload: String(row.payload ?? ''),
    }))
    return rows.length > 0 ? rows[0] : null;
  }
}
