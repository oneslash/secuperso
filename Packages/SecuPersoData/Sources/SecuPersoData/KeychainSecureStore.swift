import Foundation
import Security
import SecuPersoDomain

public final class KeychainSecureStore: SecureStore, @unchecked Sendable {
    private let service: String

    public init(service: String = "com.secuperso.app") {
        self.service = service
    }

    public func read(_ key: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw SecuPersoDataError.keychainFailure(status)
        }
    }

    public func write(_ value: Data, for key: String) throws {
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: value
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let searchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: key
            ]
            let attributesToUpdate: [String: Any] = [
                kSecValueData as String: value
            ]
            let updateStatus = SecItemUpdate(searchQuery as CFDictionary, attributesToUpdate as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw SecuPersoDataError.keychainFailure(updateStatus)
            }
            return
        }

        guard status == errSecSuccess else {
            throw SecuPersoDataError.keychainFailure(status)
        }
    }

    public func delete(_ key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecuPersoDataError.keychainFailure(status)
        }
    }
}
