import Foundation

public enum SecuPersoDataError: Error, LocalizedError {
    case fixtureFileMissing(String)
    case fixtureDecodeFailure(String)
    case sqliteFailure(String)
    case keychainFailure(OSStatus)
    case encryptionFailure
    case decryptionFailure
    case missingEncryptionKey
    case loginEventNotFound(UUID)
    case incidentNotFound(UUID)
    case invalidRemoteConfiguration(String)
    case remoteResponseInvalid
    case remoteDecodeFailure
    case remoteRequestRejected(statusCode: Int, message: String)

    public var errorDescription: String? {
        switch self {
        case .fixtureFileMissing(let filename):
            return "Fixture file not found: \(filename)."
        case .fixtureDecodeFailure(let filename):
            return "Fixture file is invalid JSON: \(filename)."
        case .sqliteFailure(let message):
            return "SQLite error: \(message)."
        case .keychainFailure(let status):
            return "Keychain error status: \(status)."
        case .encryptionFailure:
            return "Failed to encrypt payload before writing database rows."
        case .decryptionFailure:
            return "Failed to decrypt payload from database."
        case .missingEncryptionKey:
            return "Database encryption key is missing in Keychain."
        case .loginEventNotFound(let id):
            return "Login event not found: \(id.uuidString)."
        case .incidentNotFound(let id):
            return "Incident not found: \(id.uuidString)."
        case .invalidRemoteConfiguration(let message):
            return "Invalid remote data-source configuration: \(message)"
        case .remoteResponseInvalid:
            return "Remote service returned an invalid response."
        case .remoteDecodeFailure:
            return "Failed to decode remote exposure payload."
        case .remoteRequestRejected(_, let message):
            return message
        }
    }
}
