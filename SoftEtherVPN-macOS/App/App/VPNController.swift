// SoftEther VPN for macOS - app-side control of the packet tunnel: installs
// the system extension, keeps one VPN configuration in System Settings, and
// starts / stops / observes the tunnel.

import Foundation
import Combine
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

    // Every profile has its own VPN configuration and tunnel, so several can
    // be connected at the same time. Keyed by profile id.
    @Published private(set) var states: [UUID: State] = [:]
    @Published private(set) var statuses: [UUID: TunnelStatus] = [:]
    @Published var errors: [UUID: String] = [:]
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

    private var managers: [UUID: NETunnelProviderManager] = [:]
    private var observers: [UUID: NSObjectProtocol] = [:]
    private var pollTimer: Timer?

    override init() {
        super.init()
        // Also needed after an app update, to replace the installed extension
        activateExtension()
        Task { await self.loadManagers() }
    }

    func state(for id: UUID) -> State { states[id] ?? .disconnected }
    func status(for id: UUID) -> TunnelStatus { statuses[id] ?? TunnelStatus() }

    var isAnyConnected: Bool { states.values.contains(.connected) }
    var isAnyBusy: Bool {
        states.values.contains { $0 == .connecting || $0 == .reconnecting || $0 == .disconnecting }
    }

    // MARK: - System extension

    func activateExtension() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: - Configurations

    private static func profileID(of m: NETunnelProviderManager) -> UUID? {
        guard
            let json = (m.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?[TunnelKey.profile] as? Data,
            let p = try? JSONDecoder().decode(VPNProfile.self, from: json)
        else { return nil }
        return p.id
    }

    fileprivate func loadManagers() async {
        observers.values.forEach { NotificationCenter.default.removeObserver($0) }
        observers = [:]
        managers = [:]

        for m in (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? [] {
            if let id = Self.profileID(of: m), managers[id] == nil {
                managers[id] = m
                observe(m, id: id)
            } else {
                // Not one of ours any more (unreadable or duplicate)
                try? await m.removeFromPreferences()
            }
        }
    }

    private func observe(_ m: NETunnelProviderManager, id: UUID) {
        if let old = observers[id] {
            NotificationCenter.default.removeObserver(old)
        }

        observers[id] = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: m.connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.connectionStatusChanged(id) }
        }

        connectionStatusChanged(id)
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

    // The profile was deleted: stop its tunnel and remove its configuration
    func remove(profileID id: UUID) {
        if let observer = observers.removeValue(forKey: id) {
            NotificationCenter.default.removeObserver(observer)
        }

        states[id] = nil
        statuses[id] = nil
        errors[id] = nil

        guard let m = managers.removeValue(forKey: id) else { return }

        m.connection.stopVPNTunnel()
        m.removeFromPreferences { _ in }
    }

    // MARK: - Connect / disconnect

    func connect(_ profile: VPNProfile) {
        guard profile.isComplete else {
            errors[profile.id] = "Enter the server address, the Virtual Hub name and the user name first."
            return
        }

        errors[profile.id] = nil
        lastError = nil

        Task {
            // Trust on first use: fetch the server's certificate and ask once
            if profile.serverTrust == .pinned && profile.pinnedServerCertificate == nil {
                states[profile.id] = .connecting
                statuses[profile.id] = TunnelStatus(text: "Checking the server's identity…")

                let result = await ServerProbe.fetchCertificate(of: profile)

                states[profile.id] = .disconnected
                statuses[profile.id] = nil

                switch result {
                case .success(let der):
                    pendingTrust = PendingTrust(profile: profile, certificate: der,
                                                fingerprint: ServerProbe.fingerprint(of: der))
                case .failure(let error):
                    errors[profile.id] = error.localizedDescription
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
        let m = managers[profile.id] ?? NETunnelProviderManager()

        do {
            if m.connection.status != .disconnected && m.connection.status != .invalid {
                m.connection.stopVPNTunnel()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }

            try await configure(m, for: profile)

            managers[profile.id] = m
            observe(m, id: profile.id)

            var options: [String: NSObject] = [:]
            if profile.auth.needsPassword, let pw = Keychain.password(for: profile.id) {
                options[TunnelKey.password] = pw as NSString
            }

            try m.connection.startVPNTunnel(options: options)
        } catch {
            states[profile.id] = .disconnected
            errors[profile.id] = Self.describe(error)
        }
    }

    func disconnect(_ id: UUID) {
        guard let m = managers[id] else { return }

        // With on-demand on, the system would reconnect at once: a manual
        // disconnect switches it off until the user connects again
        if m.isOnDemandEnabled {
            m.isOnDemandEnabled = false
            m.saveToPreferences { _ in m.connection.stopVPNTunnel() }
        } else {
            m.connection.stopVPNTunnel()
        }
    }

    func disconnectAll() {
        managers.keys.forEach { disconnect($0) }
    }

    // MARK: - Status

    private func connectionStatusChanged(_ id: UUID) {
        guard let connection = managers[id]?.connection else { return }

        let old = state(for: id)
        let new: State

        switch connection.status {
        case .connecting: new = .connecting
        case .connected: new = .connected
        case .reasserting: new = .reconnecting
        case .disconnecting: new = .disconnecting
        default: new = .disconnected
        }

        states[id] = new

        if new == .disconnected {
            statuses[id] = nil

            // Why did it end? (startTunnel failures and cancelTunnelWithError)
            if old != .disconnected && old != .disconnecting {
                if #available(macOS 13.0, *) {
                    connection.fetchLastDisconnectError { error in
                        guard let error = error else { return }
                        Task { @MainActor in self.errors[id] = Self.describe(error) }
                    }
                }
            }
        }

        if states.values.contains(where: { $0 == .connected || $0 == .reconnecting }) {
            startPolling()
        } else {
            stopPolling()
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
        for (id, m) in managers {
            let state = self.state(for: id)
            guard state == .connected || state == .reconnecting,
                  let session = m.connection as? NETunnelProviderSession else { continue }

            try? session.sendProviderMessage(Data(TunnelKey.statusRequest.utf8)) { [weak self] reply in
                guard let reply = reply, let s = try? JSONDecoder().decode(TunnelStatus.self, from: reply) else {
                    return
                }
                Task { @MainActor in
                    if self?.state(for: id) != .disconnected { self?.statuses[id] = s }
                }
            }
        }
    }

    // Connections that would fight over the same traffic or names. macOS gives
    // overlapping routes to one tunnel only, so this is worth telling the user.
    func overlapWarning(among profiles: [VPNProfile]) -> String? {
        let active = profiles.filter { state(for: $0.id) != .disconnected }
        guard active.count > 1 else { return nil }

        // With "What the VPN server says" the outcome is known once connected
        func carriesAll(_ p: VPNProfile) -> Bool {
            switch p.tunnelMode {
            case .serverDecides: return status(for: p.id).fullTunnel
            case .includeOnly: return false
            case .full, .excludeListed: return true
            }
        }

        if active.filter(carriesAll).count > 1 {
            return "More than one connection carries all traffic. macOS sends it through only one of them. Set the others to \"Only these networks\", or have their servers announce specific networks."
        }

        let allNames = active.filter {
            $0.dnsMode == .allNames || ($0.dnsMode == .automatic && carriesAll($0))
        }
        if allNames.count > 1 {
            return "More than one connection wants to look up all names. Only one can; give the others their own DNS domains."
        }

        return nil
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
            await self.loadManagers()
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

        if let offered = Bridge.offeredServerCertificate(of: session) {
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
