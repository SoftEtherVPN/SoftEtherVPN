// SoftEther VPN for macOS - Swift conveniences over the C bridge
// (Bridge/se_bridge.h, Bridge/se_plan.h). Used by both targets.

import Foundation

// A C `char name[N]` struct member is imported as a tuple of CChar
func cString<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { raw in
        String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
    }
}

// Keeps the C strings and buffers of an se_profile alive for the duration of
// one call into the bridge (which copies what it needs).
final class BridgeProfile {
    private var strings: [UnsafeMutablePointer<CChar>] = []
    private var buffers: [UnsafeMutablePointer<UInt8>] = []
    private(set) var value = se_profile()

    init(_ p: VPNProfile, password: String?) {
        value.host = dup(p.host.trimmingCharacters(in: .whitespaces))
        value.port = UInt16(clamping: p.port)
        value.hub = dup(p.hub.trimmingCharacters(in: .whitespaces))

        value.auth_type = Int32(p.auth.rawValue)
        value.username = dup(p.username)
        value.password = dup(password ?? "")

        // Imported connection with a saved password and nothing typed since
        if p.auth == .password, (password ?? "").isEmpty,
           let hash = p.passwordHash, hash.count == Int(SE_PASSWORD_HASH_LEN) {
            value.password_hash = dup(hash).0
        }

        if p.auth == .certificate {
            (value.client_cert, value.client_cert_len) = dup(p.clientCertificate)
            (value.client_key, value.client_key_len) = dup(p.clientPrivateKey)
        }

        switch p.serverTrust {
        case .pinned:
            value.verify_server_cert = 1
            (value.pinned_server_cert, value.pinned_server_cert_len) = dup(p.pinnedServerCertificate)
        case .certificateAuthority:
            value.verify_server_cert = 1
            value.use_default_trust = 1
        case .none:
            value.verify_server_cert = 0
        }

        value.use_ipv4 = 1
        value.use_ipv6 = p.useIPv6 ? 1 : 0

        if p.macAddress.count == 6 {
            value.mac_address = dup(p.macAddress).0
        }

        value.max_connections = 1
        value.use_compress = p.useCompression ? 1 : 0
        value.disable_udp_acceleration = p.disableUDPAcceleration ? 1 : 0

        value.proxy_type = Int32(p.proxy.rawValue)
        if p.proxy != .none {
            value.proxy_host = dup(p.proxyHost.trimmingCharacters(in: .whitespaces))
            value.proxy_port = UInt16(clamping: p.proxyPort)
            value.proxy_username = dup(p.proxyUsername)
            value.proxy_password = dup(p.proxyPassword)
        }
    }

    deinit {
        strings.forEach { free($0) }
        buffers.forEach { $0.deallocate() }
    }

    private func dup(_ s: String) -> UnsafePointer<CChar>? {
        guard let p = strdup(s) else { return nil }
        strings.append(p)
        return UnsafePointer(p)
    }

    private func dup(_ d: Data?) -> (UnsafePointer<UInt8>?, Int) {
        guard let d = d, !d.isEmpty else { return (nil, 0) }
        let p = UnsafeMutablePointer<UInt8>.allocate(capacity: d.count)
        d.copyBytes(to: p, count: d.count)
        buffers.append(p)
        return (UnsafePointer(p), d.count)
    }
}

enum Bridge {
    // Start the core once per process. hamcore.se2 ships in the bundle's resources.
    static func start() -> Bool {
        guard let hamcore = Bundle.main.path(forResource: "hamcore", ofType: "se2") else {
            return false
        }
        return se_init(hamcore, NSTemporaryDirectory()) == 1
    }

    static func statusText(_ session: OpaquePointer?) -> String {
        var buf = [CChar](repeating: 0, count: 512)
        se_get_status_text(session, &buf, buf.count)
        return String(cString: buf)
    }

    static func serverAddress(_ session: OpaquePointer?) -> String? {
        var buf = [CChar](repeating: 0, count: Int(SE_ADDR_LEN))
        return se_get_server_address(session, &buf, buf.count) == 1 ? String(cString: buf) : nil
    }

    // Read a .vpn file exported by the SoftEther VPN Client into a new profile.
    // Also returns the password saved in the file for RADIUS-style sign-in, to
    // be moved into the keychain. Throws a message for the user when the file
    // is not usable.
    static func importVPNFile(_ data: Data) throws -> (profile: VPNProfile, password: String?) {
        guard start() else {
            throw BridgeError(errorDescription: "The VPN core could not be started.")
        }

        // The C struct is large and holds secrets: heap, wiped afterwards
        let imp = UnsafeMutablePointer<se_imported_profile>.allocate(capacity: 1)
        imp.initialize(to: se_imported_profile())
        defer {
            memset(imp, 0, MemoryLayout<se_imported_profile>.size)
            imp.deallocate()
        }

        var err = [CChar](repeating: 0, count: 256)
        let ok = data.withUnsafeBytes { raw in
            se_import_vpn_file(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, imp, &err, err.count)
        }

        guard ok == 1 else {
            throw BridgeError(errorDescription: String(cString: err))
        }

        guard let auth = AuthMethod(rawValue: Int(imp.pointee.auth_type)) else {
            throw BridgeError(errorDescription:
                "This connection signs in with a smart card, which this app does not support.")
        }

        func blob<T>(_ tuple: T, _ length: Int) -> Data? {
            guard length > 0 else { return nil }
            return withUnsafeBytes(of: tuple) { Data($0.prefix(length)) }
        }

        let i = imp.pointee
        var p = VPNProfile()

        p.name = cString(i.name).isEmpty ? cString(i.host) : cString(i.name)
        p.host = cString(i.host)
        p.port = Int(i.port)
        p.hub = cString(i.hub)
        p.auth = auth
        p.username = cString(i.username)
        p.passwordHash = i.has_password_hash != 0 ? blob(i.password_hash, Int(SE_PASSWORD_HASH_LEN)) : nil
        p.clientCertificate = blob(i.client_cert, i.client_cert_len)
        p.clientPrivateKey = blob(i.client_key, i.client_key_len)

        if i.verify_server_cert == 0 {
            // The file does not verify the server. Do not carry that over
            // silently: ask on first connect instead.
            p.serverTrust = .pinned
        } else if i.server_cert_len > 0 {
            p.serverTrust = .pinned
            p.pinnedServerCertificate = blob(i.server_cert, i.server_cert_len)
        } else {
            p.serverTrust = i.use_default_trust != 0 ? .certificateAuthority : .pinned
        }

        p.useCompression = i.use_compress != 0
        p.disableUDPAcceleration = i.disable_udp_acceleration != 0

        p.proxy = ProxyKind(rawValue: Int(i.proxy_type)) ?? .none
        p.proxyHost = cString(i.proxy_host)
        p.proxyPort = i.proxy_port > 0 ? Int(i.proxy_port) : p.proxyPort
        p.proxyUsername = cString(i.proxy_username)
        p.proxyPassword = cString(i.proxy_password)

        let saved = auth == .radius ? cString(i.plain_password) : ""

        return (p, saved.isEmpty ? nil : saved)
    }

    // Certificate the server offered when this session was refused, with its
    // SHA-256. Read it before se_disconnect.
    static func offeredServerCertificate(of session: OpaquePointer?) -> (der: Data, sha256: Data)? {
        var der = [UInt8](repeating: 0, count: 16384)
        var hash = [UInt8](repeating: 0, count: 32)
        let len = se_get_offered_server_cert(session, &der, der.count, &hash)
        guard len > 0, len <= der.count else { return nil }
        return (Data(der[0..<len]), Data(hash))
    }
}

struct BridgeError: LocalizedError {
    let errorDescription: String?
}
