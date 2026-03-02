import CryptoKit
import Foundation
import Security
import SecuPersoDomain

public final class EncryptionKeyProvider: @unchecked Sendable {
    private let secureStore: any SecureStore
    private let keyIdentifier: String
    private let keyLength: Int

    public init(
        secureStore: any SecureStore,
        keyIdentifier: String = "com.secuperso.app.db-key",
        keyLength: Int = 32
    ) {
        self.secureStore = secureStore
        self.keyIdentifier = keyIdentifier
        self.keyLength = keyLength
    }

    public func loadOrCreateKeyData() throws -> Data {
        if let existingData = try secureStore.read(keyIdentifier) {
            return existingData
        }

        var buffer = [UInt8](repeating: 0, count: keyLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, keyLength, &buffer)
        guard status == errSecSuccess else {
            throw SecuPersoDataError.keychainFailure(status)
        }

        let data = Data(buffer)
        try secureStore.write(data, for: keyIdentifier)
        return data
    }

    public func loadExistingKeyData() throws -> Data {
        guard let existingData = try secureStore.read(keyIdentifier) else {
            throw SecuPersoDataError.missingEncryptionKey
        }
        return existingData
    }

    public func loadOrCreateKey() throws -> SymmetricKey {
        try SymmetricKey(data: loadOrCreateKeyData())
    }

}
