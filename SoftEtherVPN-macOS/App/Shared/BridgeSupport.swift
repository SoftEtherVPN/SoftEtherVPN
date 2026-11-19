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
        value.proxy_type = Int32(SE_PROXY_DIRECT)
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

    // Certificate the server offered on the last refused attempt, with its SHA-256
    static func offeredServerCertificate() -> (der: Data, sha256: Data)? {
        var der = [UInt8](repeating: 0, count: 16384)
        var hash = [UInt8](repeating: 0, count: 32)
        let len = se_get_offered_server_cert(&der, der.count, &hash)
        guard len > 0, len <= der.count else { return nil }
        return (Data(der[0..<len]), Data(hash))
    }
}
