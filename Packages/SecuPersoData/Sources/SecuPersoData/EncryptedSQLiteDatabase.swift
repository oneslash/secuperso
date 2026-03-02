import CryptoKit
import Foundation
import SQLite3
import SecuPersoDomain

public final class EncryptedSQLiteDatabase: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.secuperso.data.sqlite")
    private let key: SymmetricKey
    private let dbURL: URL
    private var db: OpaquePointer?
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    public init(databaseURL: URL, key: SymmetricKey) throws {
        self.dbURL = databaseURL
        self.key = key
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601

        try Self.ensureParentDirectoryExists(for: databaseURL)
        try open()
        try createTables()
    }

    deinit {
        queue.sync {
            if db != nil {
                sqlite3_close(db)
                db = nil
            }
        }
    }

    public func emailFingerprint(for email: String) -> String {
        let normalized = Self.normalizeEmail(email)
        let digest = HMAC<SHA256>.authenticationCode(for: Data(normalized.utf8), using: key)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public func replaceExposures(_ exposures: [ExposureRecord]) throws {
        try queue.sync {
            try execute(sql: "BEGIN TRANSACTION")
            do {
                try execute(sql: "DELETE FROM exposures")
                for record in exposures {
                    let payload = try encrypt(record)
                    let scopeFingerprint = emailFingerprint(for: record.email)
                    try insertExposurePayload(
                        id: record.id.uuidString,
                        scopeFingerprint: scopeFingerprint,
                        updatedAt: record.foundAt,
                        payload: payload
                    )
                }
                try execute(sql: "COMMIT")
            } catch {
                try? execute(sql: "ROLLBACK")
                throw error
            }
        }
    }

    public func replaceExposures(forEmailFingerprint scopeFingerprint: String, findingRecords: [ExposureRecord]) throws {
        try queue.sync {
            try execute(sql: "BEGIN TRANSACTION")
            do {
                try deleteExposuresLocked(forEmailFingerprint: scopeFingerprint)
                for record in findingRecords {
                    let payload = try encrypt(record)
                    try insertExposurePayload(
                        id: record.id.uuidString,
                        scopeFingerprint: scopeFingerprint,
                        updatedAt: record.foundAt,
                        payload: payload
                    )
                }
                try execute(sql: "COMMIT")
            } catch {
                try? execute(sql: "ROLLBACK")
                throw error
            }
        }
    }

    public func fetchExposures() throws -> [ExposureRecord] {
        try queue.sync {
            let rows = try fetchPayloadRows(table: "exposures")
            return try rows.map { try decrypt(ExposureRecord.self, from: $0.payload) }
                .sorted(by: { $0.foundAt > $1.foundAt })
        }
    }

    public func upsertMonitoredEmail(_ monitoredEmail: MonitoredEmailAddress) throws {
        try queue.sync {
            let payload = try encrypt(monitoredEmail)
            let fingerprint = emailFingerprint(for: monitoredEmail.email)
            do {
                try insertMonitoredEmailPayload(
                    id: monitoredEmail.id.uuidString,
                    emailFingerprint: fingerprint,
                    updatedAt: monitoredEmail.lastCheckedAt ?? monitoredEmail.createdAt,
                    payload: payload
                )
            } catch let error as SecuPersoDataError {
                if case .sqliteFailure(let message) = error,
                   message.localizedCaseInsensitiveContains("UNIQUE constraint failed: monitored_emails.email_fingerprint") {
                    throw SecuPersoDataError.duplicateMonitoredEmail
                }
                throw error
            }
        }
    }

    public func fetchMonitoredEmails() throws -> [MonitoredEmailAddress] {
        try queue.sync {
            let rows = try fetchPayloadRows(table: "monitored_emails")
            return try rows.map { try decrypt(MonitoredEmailAddress.self, from: $0.payload) }
                .sorted(by: { $0.createdAt < $1.createdAt })
        }
    }

    public func fetchMonitoredEmail(id: UUID) throws -> MonitoredEmailAddress? {
        try queue.sync {
            guard let row = try fetchPayloadRow(table: "monitored_emails", id: id.uuidString) else {
                return nil
            }
            return try decrypt(MonitoredEmailAddress.self, from: row.payload)
        }
    }

    public func removeMonitoredEmail(id: UUID) throws {
        try queue.sync {
            try execute(sql: "BEGIN TRANSACTION")
            do {
                guard let fingerprint = try fetchMonitoredEmailFingerprint(id: id.uuidString) else {
                    throw SecuPersoDataError.monitoredEmailNotFound(id)
                }

                try deleteMonitoredEmailLocked(id: id.uuidString)
                try deleteExposuresLocked(forEmailFingerprint: fingerprint)
                try execute(sql: "COMMIT")
            } catch {
                try? execute(sql: "ROLLBACK")
                throw error
            }
        }
    }

    public func replaceLoginEvents(_ loginEvents: [LoginEvent]) throws {
        try queue.sync {
            try execute(sql: "BEGIN TRANSACTION")
            do {
                try execute(sql: "DELETE FROM login_events")
                for event in loginEvents {
                    let payload = try encrypt(event)
                    try insertPayload(table: "login_events", id: event.id.uuidString, updatedAt: event.occurredAt, payload: payload)
                }
                try execute(sql: "COMMIT")
            } catch {
                try? execute(sql: "ROLLBACK")
                throw error
            }
        }
    }

    public func upsertLoginEvent(_ loginEvent: LoginEvent) throws {
        try queue.sync {
            let payload = try encrypt(loginEvent)
            try insertPayload(table: "login_events", id: loginEvent.id.uuidString, updatedAt: loginEvent.occurredAt, payload: payload)
        }
    }

    public func fetchLoginEvents() throws -> [LoginEvent] {
        try queue.sync {
            let rows = try fetchPayloadRows(table: "login_events")
            return try rows.map { try decrypt(LoginEvent.self, from: $0.payload) }
                .sorted(by: { $0.occurredAt > $1.occurredAt })
        }
    }

    public func fetchLoginEvent(id: UUID) throws -> LoginEvent? {
        try queue.sync {
            guard let row = try fetchPayloadRow(table: "login_events", id: id.uuidString) else {
                return nil
            }
            return try decrypt(LoginEvent.self, from: row.payload)
        }
    }

    public func upsertIncident(_ incident: IncidentCase) throws {
        try queue.sync {
            let payload = try encrypt(incident)
            try insertPayload(table: "incidents", id: incident.id.uuidString, updatedAt: incident.createdAt, payload: payload)
        }
    }

    public func fetchIncident(id: UUID) throws -> IncidentCase? {
        try queue.sync {
            guard let row = try fetchPayloadRow(table: "incidents", id: id.uuidString) else {
                return nil
            }
            return try decrypt(IncidentCase.self, from: row.payload)
        }
    }

    public func fetchIncidents() throws -> [IncidentCase] {
        try queue.sync {
            let rows = try fetchPayloadRows(table: "incidents")
            return try rows.map { try decrypt(IncidentCase.self, from: $0.payload) }
                .sorted(by: { $0.createdAt > $1.createdAt })
        }
    }

    public func upsertProviderConnection(_ connection: ProviderConnection) throws {
        try queue.sync {
            let payload = try encrypt(connection)
            try insertPayload(table: "provider_connections", id: connection.id.rawValue, updatedAt: connection.lastUpdatedAt, payload: payload)
        }
    }

    public func fetchProviderConnections() throws -> [ProviderConnection] {
        try queue.sync {
            let rows = try fetchPayloadRows(table: "provider_connections")
            return try rows.map { try decrypt(ProviderConnection.self, from: $0.payload) }
                .sorted(by: { $0.id.rawValue < $1.id.rawValue })
        }
    }

    public func appendAuditEvent(_ event: String, createdAt: Date = Date()) throws {
        try queue.sync {
            var statement: OpaquePointer?
            defer { sqlite3_finalize(statement) }

            let sql = "INSERT INTO app_audit_events (created_at, event) VALUES (?, ?);"
            guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
                throw sqliteError()
            }

            sqlite3_bind_double(statement, 1, createdAt.timeIntervalSince1970)
            sqlite3_bind_text(statement, 2, event, -1, sqliteTransient)

            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw sqliteError()
            }
        }
    }

    private static func ensureParentDirectoryExists(for url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private static func normalizeEmail(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private func open() throws {
        try queue.sync {
            let result = sqlite3_open(dbURL.path, &db)
            guard result == SQLITE_OK else {
                throw sqliteError()
            }
        }
    }

    private func createTables() throws {
        try queue.sync {
            try execute(sql: """
                CREATE TABLE IF NOT EXISTS exposures (
                    id TEXT PRIMARY KEY NOT NULL,
                    scope_fingerprint TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try ensureExposureScopeColumnExists()
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_exposures_updated_at ON exposures(updated_at);")
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_exposures_scope_fingerprint ON exposures(scope_fingerprint);")

            try execute(sql: """
                CREATE TABLE IF NOT EXISTS monitored_emails (
                    id TEXT PRIMARY KEY NOT NULL,
                    email_fingerprint TEXT NOT NULL UNIQUE,
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_monitored_emails_updated_at ON monitored_emails(updated_at);")

            try execute(sql: """
                CREATE TABLE IF NOT EXISTS login_events (
                    id TEXT PRIMARY KEY NOT NULL,
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_login_events_updated_at ON login_events(updated_at);")

            try execute(sql: """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY NOT NULL,
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);")

            try execute(sql: """
                CREATE TABLE IF NOT EXISTS provider_connections (
                    id TEXT PRIMARY KEY NOT NULL,
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_provider_connections_updated_at ON provider_connections(updated_at);")

            try execute(sql: """
                CREATE TABLE IF NOT EXISTS app_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    event TEXT NOT NULL
                );
            """)
        }
    }

    private func ensureExposureScopeColumnExists() throws {
        guard try !hasColumn(table: "exposures", column: "scope_fingerprint") else {
            return
        }

        try execute(sql: "ALTER TABLE exposures ADD COLUMN scope_fingerprint TEXT NOT NULL DEFAULT '';")
    }

    private func hasColumn(table: String, column: String) throws -> Bool {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "PRAGMA table_info(\(table));"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        while sqlite3_step(statement) == SQLITE_ROW {
            guard let nameText = sqlite3_column_text(statement, 1) else {
                continue
            }
            if String(cString: nameText) == column {
                return true
            }
        }

        return false
    }

    private func execute(sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw sqliteError()
        }
    }

    private func insertPayload(table: String, id: String, updatedAt: Date, payload: Data) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "INSERT INTO \(table) (id, updated_at, payload) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, payload = excluded.payload;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)
        sqlite3_bind_double(statement, 2, updatedAt.timeIntervalSince1970)
        _ = payload.withUnsafeBytes { rawBuffer in
            sqlite3_bind_blob(statement, 3, rawBuffer.baseAddress, Int32(payload.count), sqliteTransient)
        }

        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError()
        }
    }

    private func insertExposurePayload(id: String, scopeFingerprint: String, updatedAt: Date, payload: Data) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = """
        INSERT INTO exposures (id, scope_fingerprint, updated_at, payload)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            scope_fingerprint = excluded.scope_fingerprint,
            updated_at = excluded.updated_at,
            payload = excluded.payload;
        """

        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)
        sqlite3_bind_text(statement, 2, scopeFingerprint, -1, sqliteTransient)
        sqlite3_bind_double(statement, 3, updatedAt.timeIntervalSince1970)
        _ = payload.withUnsafeBytes { rawBuffer in
            sqlite3_bind_blob(statement, 4, rawBuffer.baseAddress, Int32(payload.count), sqliteTransient)
        }

        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError()
        }
    }

    private func insertMonitoredEmailPayload(id: String, emailFingerprint: String, updatedAt: Date, payload: Data) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = """
        INSERT INTO monitored_emails (id, email_fingerprint, updated_at, payload)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            email_fingerprint = excluded.email_fingerprint,
            updated_at = excluded.updated_at,
            payload = excluded.payload;
        """

        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)
        sqlite3_bind_text(statement, 2, emailFingerprint, -1, sqliteTransient)
        sqlite3_bind_double(statement, 3, updatedAt.timeIntervalSince1970)
        _ = payload.withUnsafeBytes { rawBuffer in
            sqlite3_bind_blob(statement, 4, rawBuffer.baseAddress, Int32(payload.count), sqliteTransient)
        }

        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError()
        }
    }

    private func deleteExposuresLocked(forEmailFingerprint scopeFingerprint: String) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "DELETE FROM exposures WHERE scope_fingerprint = ?;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, scopeFingerprint, -1, sqliteTransient)

        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError()
        }
    }

    private func deleteMonitoredEmailLocked(id: String) throws {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "DELETE FROM monitored_emails WHERE id = ?;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)

        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw sqliteError()
        }
    }

    private func fetchMonitoredEmailFingerprint(id: String) throws -> String? {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "SELECT email_fingerprint FROM monitored_emails WHERE id = ? LIMIT 1;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)

        guard sqlite3_step(statement) == SQLITE_ROW else {
            return nil
        }

        guard let text = sqlite3_column_text(statement, 0) else {
            return nil
        }

        return String(cString: text)
    }

    private func fetchPayloadRows(table: String) throws -> [(id: String, updatedAt: Double, payload: Data)] {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "SELECT id, updated_at, payload FROM \(table) ORDER BY updated_at DESC;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        var rows: [(id: String, updatedAt: Double, payload: Data)] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let idText = sqlite3_column_text(statement, 0) else { continue }
            let id = String(cString: idText)
            let updatedAt = sqlite3_column_double(statement, 1)
            let bytes = sqlite3_column_blob(statement, 2)
            let length = Int(sqlite3_column_bytes(statement, 2))
            let payload = bytes.map { Data(bytes: $0, count: length) } ?? Data()
            rows.append((id, updatedAt, payload))
        }

        return rows
    }

    private func fetchPayloadRow(table: String, id: String) throws -> (id: String, updatedAt: Double, payload: Data)? {
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }

        let sql = "SELECT id, updated_at, payload FROM \(table) WHERE id = ? LIMIT 1;"
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else {
            throw sqliteError()
        }

        sqlite3_bind_text(statement, 1, id, -1, sqliteTransient)

        guard sqlite3_step(statement) == SQLITE_ROW else {
            return nil
        }

        guard let idText = sqlite3_column_text(statement, 0) else {
            return nil
        }
        let rowID = String(cString: idText)
        let updatedAt = sqlite3_column_double(statement, 1)
        let bytes = sqlite3_column_blob(statement, 2)
        let length = Int(sqlite3_column_bytes(statement, 2))
        let payload = bytes.map { Data(bytes: $0, count: length) } ?? Data()
        return (rowID, updatedAt, payload)
    }

    private func encrypt<T: Encodable>(_ value: T) throws -> Data {
        do {
            let payload = try encoder.encode(value)
            let sealed = try AES.GCM.seal(payload, using: key)
            guard let combined = sealed.combined else {
                throw SecuPersoDataError.encryptionFailure
            }
            return combined
        } catch {
            throw SecuPersoDataError.encryptionFailure
        }
    }

    private func decrypt<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            return try decoder.decode(T.self, from: decryptedData)
        } catch {
            throw SecuPersoDataError.decryptionFailure
        }
    }

    private func sqliteError() -> SecuPersoDataError {
        let message: String
        if let cString = sqlite3_errmsg(db) {
            message = String(cString: cString)
        } else {
            message = "Unknown SQLite failure"
        }
        return .sqliteFailure(message)
    }
}
