import CryptoKit
import XCTest
import SecuPersoData
import SecuPersoDomain

final class EncryptionAndDatabaseTests: XCTestCase {
    func testLoadExistingKeyThrowsWhenMissing() {
        let secureStore = InMemorySecureStore()
        let provider = EncryptionKeyProvider(secureStore: secureStore, keyIdentifier: "missing-key")

        XCTAssertThrowsError(try provider.loadExistingKeyData()) { error in
            guard case SecuPersoDataError.missingEncryptionKey = error else {
                XCTFail("Expected missingEncryptionKey, got \(error)")
                return
            }
        }
    }

    func testLoadOrCreateKeyIsStableAcrossReads() throws {
        let secureStore = InMemorySecureStore()
        let provider = EncryptionKeyProvider(secureStore: secureStore, keyIdentifier: "db-key")

        let first = try provider.loadOrCreateKeyData()
        let second = try provider.loadOrCreateKeyData()

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.count, 32)
    }

    func testEncryptedDatabaseRoundTrip() throws {
        let database = try makeDatabase()

        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Mock Source",
            foundAt: Date(),
            severity: .high,
            status: .open,
            remediation: "Rotate password"
        )

        let login = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(),
            device: "Mac",
            ipAddress: "203.0.113.99",
            location: "US",
            reason: "Mock",
            suspicious: true,
            expected: false
        )

        try database.replaceExposures([exposure])
        try database.replaceLoginEvents([login])

        let savedExposures = try database.fetchExposures()
        let savedLogins = try database.fetchLoginEvents()

        XCTAssertEqual(savedExposures.count, 1)
        XCTAssertEqual(savedLogins.count, 1)
        XCTAssertEqual(savedExposures.first?.email, exposure.email)
        XCTAssertEqual(savedLogins.first?.ipAddress, login.ipAddress)
    }

    func testFetchLoginEventByIDReturnsExactRow() throws {
        let database = try makeDatabase()

        let first = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 100),
            device: "Mac",
            ipAddress: "203.0.113.11",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let second = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Windows",
            ipAddress: "198.51.100.22",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        try database.replaceLoginEvents([first, second])

        let fetched = try database.fetchLoginEvent(id: second.id)
        XCTAssertEqual(fetched?.id, second.id)
        XCTAssertEqual(fetched?.ipAddress, second.ipAddress)
    }

    func testFetchIncidentByIDReturnsExactRow() throws {
        let database = try makeDatabase()

        let first = IncidentCase(
            id: UUID(),
            title: "First",
            severity: .medium,
            createdAt: Date(timeIntervalSince1970: 100),
            status: .open,
            linkedLoginEventID: UUID(),
            notes: "first",
            resolvedAt: nil
        )
        let second = IncidentCase(
            id: UUID(),
            title: "Second",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 200),
            status: .open,
            linkedLoginEventID: UUID(),
            notes: "second",
            resolvedAt: nil
        )

        try database.upsertIncident(first)
        try database.upsertIncident(second)

        let fetched = try database.fetchIncident(id: first.id)
        XCTAssertEqual(fetched?.id, first.id)
        XCTAssertEqual(fetched?.title, "First")
    }

    func testFetchExposuresAndLoginsAreSortedDescendingByUpdatedAt() throws {
        let database = try makeDatabase()

        let olderExposure = ExposureRecord(
            id: UUID(),
            email: "older@example.com",
            source: "Old Source",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .low,
            status: .open,
            remediation: "Rotate password"
        )
        let newerExposure = ExposureRecord(
            id: UUID(),
            email: "newer@example.com",
            source: "New Source",
            foundAt: Date(timeIntervalSince1970: 200),
            severity: .high,
            status: .open,
            remediation: "Enable MFA"
        )

        let olderLogin = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Mac",
            ipAddress: "203.0.113.31",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let newerLogin = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 400),
            device: "Windows",
            ipAddress: "198.51.100.44",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )

        try database.replaceExposures([olderExposure, newerExposure])
        try database.replaceLoginEvents([olderLogin, newerLogin])

        let exposures = try database.fetchExposures()
        let logins = try database.fetchLoginEvents()

        XCTAssertEqual(exposures.first?.id, newerExposure.id)
        XCTAssertEqual(exposures.last?.id, olderExposure.id)
        XCTAssertEqual(logins.first?.id, newerLogin.id)
        XCTAssertEqual(logins.last?.id, olderLogin.id)
    }

    private func makeDatabase() throws -> EncryptedSQLiteDatabase {
        let databaseURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("secuperso.sqlite")

        return try EncryptedSQLiteDatabase(databaseURL: databaseURL, key: SymmetricKey(size: .bits256))
    }
}

private final class InMemorySecureStore: SecureStore, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    func read(_ key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    func write(_ value: Data, for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = value
    }
}
