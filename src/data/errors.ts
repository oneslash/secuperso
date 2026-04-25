export type SecuPersoDataError =
  | { kind: 'fixtureFileMissing'; filename: string }
  | { kind: 'fixtureDecodeFailure'; filename: string }
  | { kind: 'sqliteFailure'; message: string }
  | { kind: 'keychainFailure'; status: number }
  | { kind: 'encryptionFailure' }
  | { kind: 'decryptionFailure' }
  | { kind: 'missingEncryptionKey' }
  | { kind: 'loginEventNotFound'; id: string }
  | { kind: 'incidentNotFound'; id: string }
  | { kind: 'monitoredEmailNotFound'; id: string }
  | { kind: 'duplicateMonitoredEmail' }
  | { kind: 'invalidRemoteConfiguration'; message: string }
  | { kind: 'remoteResponseInvalid' }
  | { kind: 'remoteDecodeFailure' }
  | { kind: 'remoteRequestRejected'; statusCode: number; message: string }
  | { kind: 'exposureBatchAborted'; reason: string }
  | { kind: 'migrationFailure'; message: string };

export function errorDescription(error: SecuPersoDataError): string {
  switch (error.kind) {
    case 'fixtureFileMissing': return `Fixture file not found: ${error.filename}.`;
    case 'fixtureDecodeFailure': return `Fixture file is invalid JSON: ${error.filename}.`;
    case 'sqliteFailure': return `SQLite error: ${error.message}.`;
    case 'keychainFailure': return `Keychain error status: ${error.status}.`;
    case 'encryptionFailure': return 'Failed to encrypt payload before writing database rows.';
    case 'decryptionFailure': return 'Failed to decrypt payload from database.';
    case 'missingEncryptionKey': return 'Database encryption key is missing in Keychain.';
    case 'loginEventNotFound': return `Login event not found: ${error.id}.`;
    case 'incidentNotFound': return `Incident not found: ${error.id}.`;
    case 'monitoredEmailNotFound': return `Monitored email was not found: ${error.id}.`;
    case 'duplicateMonitoredEmail': return 'This email is already being monitored.';
    case 'invalidRemoteConfiguration': return `Invalid remote data-source configuration: ${error.message}`;
    case 'remoteResponseInvalid': return 'Remote service returned an invalid response.';
    case 'remoteDecodeFailure': return 'Failed to decode remote exposure payload.';
    case 'remoteRequestRejected': return error.message;
    case 'exposureBatchAborted': return error.reason;
    case 'migrationFailure': return `Data migration failed: ${error.message}`;
  }
}

export function createDataError(kind: SecuPersoDataError['kind'], ...args: any[]): SecuPersoDataError {
  switch (kind) {
    case 'fixtureFileMissing': return { kind, filename: args[0] as string };
    case 'fixtureDecodeFailure': return { kind, filename: args[0] as string };
    case 'sqliteFailure': return { kind, message: args[0] as string };
    case 'keychainFailure': return { kind, status: args[0] as number };
    case 'loginEventNotFound': return { kind, id: args[0] as string };
    case 'incidentNotFound': return { kind, id: args[0] as string };
    case 'monitoredEmailNotFound': return { kind, id: args[0] as string };
    case 'invalidRemoteConfiguration': return { kind, message: args[0] as string };
    case 'remoteRequestRejected': return { kind, statusCode: args[0] as number, message: args[1] as string };
    case 'exposureBatchAborted': return { kind, reason: args[0] as string };
    case 'migrationFailure': return { kind, message: args[0] as string };
    default: return { kind } as SecuPersoDataError;
  }
}