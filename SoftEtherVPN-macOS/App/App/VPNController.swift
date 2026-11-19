// SoftEther VPN for macOS - app-side control of the packet tunnel: installs
// the system extension, keeps one VPN configuration in System Settings, and
// starts / stops / observes the tunnel.

import Foundation
import NetworkExtension
import SystemExtensions
import CryptoKit

@MainActor
final class VPNController: NSObject, ObservableObject {
    static let extensionBundleID = "org.softether.vpnclient.macos.tunnel"

    enum State: Equatable {
        case disconnected
        case connecting
        case connected
        case reconnecting
        case disconnecting
    }

    @Published private(set) var state = State.disconnected
    @Published private(set) var activeProfileID: UUID?
    @Published private(set) var status = TunnelStatus()
    @Published var lastError: String?
    @Published var extensionNeedsApproval = false
    // Set when a server certificate has to be confirmed by the user
    @Published var pendingTrust: PendingTrust?

    struct PendingTrust: Identifiable {
        let id = UUID()
        let profile: VPNProfile
        let certificate: Data
        let fingerprint: String
    }

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTimer: Timer?

    override init() {
        super.init()
        Task { await self.loadManager() }
    }

    // MARK: - System extension

    func activateExtension() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Configuration

    private func loadManager() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        let m = managers.first ?? NETunnelProviderManager()
        manager = m

        if let json = (m.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?[TunnelKey.profile] as? Data,
           let p = try? JSONDecoder().decode(VPNProfile.self, from: json) {
            activeProfileID = p.id
        }

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.connectionStatusChanged() }
        }

        connectionStatusChanged()
    }

    private func configure(_ m: NETunnelProviderManager, for profile: VPNProfile) async throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.extensionBundleID
        proto.serverAddress = profile.host

        var configuration: [String: Any] = [TunnelKey.profile: try JSONEncoder().encode(profile)]

        // A connection that connects by itself is started by the system
        // without this app, so its password has to travel with the configuration
        if profile.connectAutomatically, profile.auth.needsPassword,
           let pw = Keychain.password(for: profile.id) {
            configuration[TunnelKey.password] = pw
        }

        proto.providerConfiguration = configuration

        m.protocolConfiguration = proto
        m.localizedDescription = profile.name
        m.isEnabled = true
        m.onDemandRules = profile.connectAutomatically ? [NEOnDemandRuleConnect()] : []
        m.isOnDemandEnabled = profile.connectAutomatically

        try await m.saveToPreferences()
        // The saved configuration has to be reloaded before it can be started
        try await m.loadFromPreferences()
    }

    // MARK: - Connect / disconnect

    func connect(_ profile: VPNProfile) {
        guard profile.isComplete else {
            lastError = "Enter the server address, the Virtual Hub name and the user name first."
            return
        }

        lastError = nil

        Task {
            // Trust on first use: fetch the server's certificate and ask once
            if profile.serverTrust == .pinned && profile.pinnedServerCertificate == nil {
                state = .connecting
                activeProfileID = profile.id
                status.text = "Checking the server's identity..."

                switch await ServerProbe.fetchCertificate(of: profile) {
                case .success(let der):
                    state = .disconnected
                    pendingTrust = PendingTrust(profile: profile, certificate: der,
                                                fingerprint: ServerProbe.fingerprint(of: der))
                case .failure(let error):
                    state = .disconnected
                    lastError = error.localizedDescription
                }
                return
            }

            await start(profile)
        }
    }

    // The user accepted the certificate shown for a pending connection
    func trustAndConnect(_ pending: PendingTrust, store: ProfileStore) {
        var profile = pending.profile
        profile.pinnedServerCertificate = pending.certificate
        store.update(profile)
        pendingTrust = nil

        Task { await start(profile) }
    }

    private func start(_ profile: VPNProfile) async {
        guard let m = manager else { return }

        do {
            if m.connection.status != .disconnected && m.connection.status != .invalid {
                m.connection.stopVPNTunnel()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }

            try await configure(m, for: profile)
            activeProfileID = profile.id

            var options: [String: NSObject] = [:]
            if profile.auth.needsPassword, let pw = Keychain.password(for: profile.id) {
                options[TunnelKey.password] = pw as NSString
            }

            try m.connection.startVPNTunnel(options: options)
        } catch {
            state = .disconnected
            lastError = Self.describe(error)
        }
    }

    func disconnect() {
        guard let m = manager else { return }

        // With on-demand on, the system would reconnect at once: a manual
        // disconnect switches it off until the user connects again
        if m.isOnDemandEnabled {
            m.isOnDemandEnabled = false
            m.saveToPreferences { _ in m.connection.stopVPNTunnel() }
        } else {
            m.connection.stopVPNTunnel()
        }
    }

    // MARK: - Status

    private func connectionStatusChanged() {
        guard let connection = manager?.connection else { return }

        let old = state

        switch connection.status {
        case .connecting: state = .connecting
        case .connected: state = .connected
        case .reasserting: state = .reconnecting
        case .disconnecting: state = .disconnecting
        default: state = .disconnected
        }

        if state == .connected || state == .reconnecting {
            startPolling()
        } else {
            stopPolling()
        }

        if state == .disconnected {
            status = TunnelStatus()

            // Why did it end? (startTunnel failures and cancelTunnelWithError)
            if old != .disconnected && old != .disconnecting {
                if #available(macOS 13.0, *) {
                    connection.fetchLastDisconnectError { error in
                        guard let error = error else { return }
                        Task { @MainActor in self.lastError = Self.describe(error) }
                    }
                }
            }
        }
    }

    private func startPolling() {
        guard pollTimer == nil else { return }

        pollTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollStatus() }
        }
        pollStatus()
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func pollStatus() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }

        try? session.sendProviderMessage(Data(TunnelKey.statusRequest.utf8)) { [weak self] reply in
            guard let reply = reply, let s = try? JSONDecoder().decode(TunnelStatus.self, from: reply) else {
                return
            }
            Task { @MainActor in self?.status = s }
        }
    }

    private static func describe(_ error: Error) -> String {
        let ns = error as NSError

        if ns.domain == NEVPNErrorDomain && ns.code == NEVPNError.Code.configurationReadWriteFailed.rawValue {
            return "The VPN configuration could not be saved. Allow it in System Settings and try again."
        }

        return error.localizedDescription
    }
}

extension VPNController: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in self.extensionNeedsApproval = true }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            self.extensionNeedsApproval = false
            await self.loadManager()
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            self.lastError = "The network extension could not be installed: \(error.localizedDescription)"
        }
    }
}

// Fetches the certificate a VPN server presents, without logging in: a dial
// with verification on and nothing trusted is refused by the core right after
// the TLS handshake and reports the certificate it saw.
enum ServerProbe {
    struct ProbeError: LocalizedError {
        let errorDescription: String?
    }

    static func fetchCertificate(of profile: VPNProfile) async -> Result<Data, Error> {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: probe(profile))
            }
        }
    }

    private static func probe(_ profile: VPNProfile) -> Result<Data, Error> {
        guard Bridge.start() else {
            return .failure(ProbeError(errorDescription: "The VPN core could not be started."))
        }

        var probeProfile = profile
        probeProfile.serverTrust = .pinned
        probeProfile.pinnedServerCertificate = nil
        probeProfile.auth = .anonymous
        probeProfile.useIPv6 = false

        let bridgeProfile = BridgeProfile(probeProfile, password: nil)
        var err = [CChar](repeating: 0, count: 256)
        var p = bridgeProfile.value

        let started = withExtendedLifetime(bridgeProfile) {
            se_connect(&p, &err, err.count)
        }

        guard let session = started else {
            return .failure(ProbeError(errorDescription: String(cString: err)))
        }

        defer { se_disconnect(session) }

        let deadline = Date().addingTimeInterval(30)
        while se_get_status(session) == Int32(SE_STATUS_CONNECTING) && Date() < deadline {
            usleep(100_000)
        }

        if let offered = Bridge.offeredServerCertificate() {
            return .success(offered.der)
        }

        let text = Bridge.statusText(session)
        return .failure(ProbeError(errorDescription:
            text == "Disconnected." ? "The server could not be reached." : text))
    }

    static func fingerprint(of der: Data) -> String {
        SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
