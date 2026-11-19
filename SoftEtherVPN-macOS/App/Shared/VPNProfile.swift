// SoftEther VPN for macOS - connection profile shared by the app and the
// packet tunnel provider. The app owns the profiles; the provider receives the
// one being connected as JSON in its providerConfiguration.

import Foundation

enum AuthMethod: Int, Codable, CaseIterable, Identifiable {
    case anonymous = 0          // SE_AUTH_ANONYMOUS
    case password = 1           // SE_AUTH_PASSWORD
    case radius = 2             // SE_AUTH_PLAIN_PASSWORD
    case certificate = 3        // SE_AUTH_CERT

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .anonymous: return "Anonymous"
        case .password: return "Password"
        case .radius: return "RADIUS or domain password"
        case .certificate: return "Client certificate"
        }
    }

    var needsPassword: Bool { self == .password || self == .radius }
}

enum TunnelMode: Int, Codable, CaseIterable, Identifiable {
    case full = 0               // SE_TUNNEL_FULL
    case includeOnly = 1        // SE_TUNNEL_INCLUDE
    case excludeListed = 2      // SE_TUNNEL_EXCLUDE

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .full: return "All traffic"
        case .includeOnly: return "Only these networks"
        case .excludeListed: return "All traffic except these networks"
        }
    }
}

enum DNSMode: Int, Codable, CaseIterable, Identifiable {
    case automatic = 0          // SE_DNS_AUTO
    case allNames = 1           // SE_DNS_ALL
    case splitDomains = 2       // SE_DNS_SPLIT
    case off = 3                // SE_DNS_OFF

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .automatic: return "Automatic"
        case .allNames: return "Use the VPN's DNS for all names"
        case .splitDomains: return "Use the VPN's DNS only for these domains"
        case .off: return "Don't change DNS"
        }
    }
}

enum ServerTrust: Int, Codable, CaseIterable, Identifiable {
    case pinned = 0             // trust on first use: the certificate the user accepted
    case certificateAuthority = 1   // public CA chain + host name
    case none = 2               // no verification (insecure)

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .pinned: return "Ask once, then remember the server's certificate"
        case .certificateAuthority: return "Require a certificate from a public authority"
        case .none: return "Don't verify (insecure)"
        }
    }
}

struct VPNProfile: Codable, Identifiable, Equatable {
    var id = UUID()
    var name = "New Connection"

    var host = ""
    var port = 443
    var hub = ""

    var auth = AuthMethod.password
    var username = ""
    // The password is never stored here: it lives in the login keychain and is
    // handed to the provider when the tunnel is started.
    var clientCertificate: Data?        // DER or PEM
    var clientPrivateKey: Data?         // DER or PEM, unencrypted

    var serverTrust = ServerTrust.pinned
    var pinnedServerCertificate: Data?  // DER

    var tunnelMode = TunnelMode.full
    var networks = ""                   // free text, see se_plan.h
    var usePushedRoutes = true

    var dnsMode = DNSMode.automatic
    var dnsDomains = ""
    var dnsServers = ""

    var useIPv6 = false

    // Inner MAC of the virtual adapter: stable per profile so the hub's DHCP
    // server keeps handing out the same address.
    var macAddress = VPNProfile.randomMAC()

    var useCompression = false
    var disableUDPAcceleration = false

    static func randomMAC() -> Data {
        var bytes = (0..<6).map { _ in UInt8.random(in: 0...255) }
        bytes[0] = (bytes[0] & 0xFE) | 0x02     // locally administered, unicast
        return Data(bytes)
    }

    var isComplete: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty &&
            !hub.trimmingCharacters(in: .whitespaces).isEmpty &&
            (auth == .anonymous || !username.isEmpty)
    }
}

// Keys of the dictionaries exchanged between the app and the provider
enum TunnelKey {
    static let profile = "profile"          // providerConfiguration: JSON of VPNProfile
    static let password = "password"        // startVPNTunnel options
    static let statusRequest = "status"     // sendProviderMessage payload
}

// Reply of the provider to a status request
struct TunnelStatus: Codable, Equatable {
    var text = ""
    var connected = false
    var address = ""
    var address6 = ""
    var server = ""
    var dnsServers: [String] = []
    var dnsDomains: [String] = []       // empty with dnsServers set = all names
    var routedNetworks: [String] = []
    var bypassedNetworks: [String] = []
    var warnings: [String] = []
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
}
