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

    public func replaceExposures(_ exposures: [ExposureRecord]) throws {
        try queue.sync {
            try execute(sql: "BEGIN TRANSACTION")
            do {
                try execute(sql: "DELETE FROM exposures")
                for record in exposures {
                    let payload = try encrypt(record)
                    try insertPayload(table: "exposures", id: record.id.uuidString, updatedAt: record.foundAt, payload: payload)
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
                    updated_at REAL NOT NULL,
                    payload BLOB NOT NULL
                );
            """)
            try execute(sql: "CREATE INDEX IF NOT EXISTS idx_exposures_updated_at ON exposures(updated_at);")

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
