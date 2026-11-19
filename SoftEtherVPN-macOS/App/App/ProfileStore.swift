// SoftEther VPN for macOS - profiles on disk, passwords in the login keychain.

import Foundation
import Security

final class ProfileStore: ObservableObject {
    @Published var profiles: [VPNProfile] = [] {
        didSet { save() }
    }

    private let fileURL: URL

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SoftEtherVPN", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("profiles.json")

        if let data = try? Data(contentsOf: fileURL),
           let loaded = try? JSONDecoder().decode([VPNProfile].self, from: data) {
            profiles = loaded
        }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(profiles) else { return }
        // Client private keys live in this file: owner-only
        try? data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    func update(_ profile: VPNProfile) {
        if let i = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[i] = profile
        } else {
            profiles.append(profile)
        }
    }

    func delete(_ profile: VPNProfile) {
        Keychain.deletePassword(for: profile.id)
        profiles.removeAll { $0.id == profile.id }
    }
}

enum Keychain {
    private static let service = "org.softether.vpnclient.macos"

    private static func query(_ id: UUID) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id.uuidString,
        ]
    }

    static func password(for id: UUID) -> String? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne

        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    static func setPassword(_ password: String, for id: UUID) {
        deletePassword(for: id)
        guard !password.isEmpty else { return }

        var q = query(id)
        q[kSecValueData as String] = Data(password.utf8)
        SecItemAdd(q as CFDictionary, nil)
    }

    static func deletePassword(for id: UUID) {
        SecItemDelete(query(id) as CFDictionary)
    }
}
