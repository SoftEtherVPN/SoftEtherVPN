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
    // Server certificates waiting for the user's confirmation, one per profile
    @Published private(set) var pendingTrusts: [PendingTrust] = []

    struct PendingTrust: Identifiable {
        let id = UUID()
        let profile: VPNProfile
        let certificate: Data
        let fingerprint: String
    }

    private var managers: [UUID: NETunnelProviderManager] = [:]
    private var observers: [UUID: NSObjectProtocol] = [:]
    private var pollTimer: Timer?

    // Profiles between the user's click and the system's first status report
    private var starting: Set<UUID> = []
    // Profiles the user switched off by hand: "connect automatically" stays
    // off for them until the user connects again
    private var userStopped: Set<UUID> = []
    // Profiles deleted while a start was in flight
    private var removed: Set<UUID> = []
    private var syncTask: Task<Void, Never>?

    // The ids of the profiles that exist, or nil when that is not known (the
    // profiles file could not be read). Used to clean up VPN configurations
    // whose profile is gone.
    private let knownProfileIDs: () -> Set<UUID>?

    init(knownProfileIDs: @escaping () -> Set<UUID>?) {
        self.knownProfileIDs = knownProfileIDs
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

    private static func storedProfile(of m: NETunnelProviderManager) -> VPNProfile? {
        guard
            let json = (m.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?[TunnelKey.profile] as? Data
        else { return nil }
        return try? JSONDecoder().decode(VPNProfile.self, from: json)
    }

    // Read the saved VPN configurations and remove the orphaned ones: a
    // configuration whose profile no longer exists has no switch in the app,
    // yet would still show in System Settings and, with "connect
    // automatically", keep connecting.
    //
    // Everything after the read runs without suspending, so two overlapping
    // calls cannot see each other's half-built state. Two objects for the
    // same configuration from two such calls are not duplicates: only what
    // one read returns twice is.
    fileprivate func loadManagers() async {
        guard let loaded = try? await NETunnelProviderManager.loadAllFromPreferences() else { return }

        // nil: the profiles are not known right now, so nothing is an orphan
        let known = knownProfileIDs()

        var found: [UUID: NETunnelProviderManager] = [:]
        for m in loaded {
            let id = Self.storedProfile(of: m)?.id

            if let id = id, found[id] == nil,
               known == nil || known!.contains(id) || starting.contains(id) {
                // A start in flight already holds the object for its profile
                found[id] = managers[id] ?? m
            } else if known != nil {
                // No profile for it (deleted, or the configuration is not
                // readable as one of this app's), or a second configuration
                // for a profile that already has one
                Self.discard(m)
            }
        }

        // Keep what a start created meanwhile
        for (id, m) in managers where found[id] == nil && starting.contains(id) {
            found[id] = m
        }

        observers.values.forEach { NotificationCenter.default.removeObserver($0) }
        observers = [:]
        managers = found

        for (id, m) in found {
            observe(m, id: id)
        }
    }

    // Stop and delete a VPN configuration that belongs to no profile
    private static func discard(_ m: NETunnelProviderManager) {
        m.isOnDemandEnabled = false
        m.connection.stopVPNTunnel()
        m.removeFromPreferences { _ in }
    }

    // The list of profiles changed: drop the configurations of profiles that
    // are gone. (Deleting a profile in the app goes through remove(profileID:)
    // already; this catches every other way a profile can disappear.)
    func removeOrphans() {
        guard let known = knownProfileIDs() else { return }

        for (id, m) in managers where !known.contains(id) && !starting.contains(id) {
            if let observer = observers.removeValue(forKey: id) {
                NotificationCenter.default.removeObserver(observer)
            }

            managers[id] = nil
            states[id] = nil
            statuses[id] = nil
            errors[id] = nil
            userStopped.remove(id)

            Self.discard(m)
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

    private func wantsOnDemand(_ profile: VPNProfile) -> Bool {
        profile.connectAutomatically && !userStopped.contains(profile.id)
    }

    private func configure(_ m: NETunnelProviderManager, for profile: VPNProfile) async throws {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.extensionBundleID
        proto.serverAddress = profile.host

        // The system keeps this outside the keychain. A profile the user
        // connects by hand is stored without its secrets, which then travel
        // with each start request. One that connects by itself is started by
        // the system without this app, so it has to carry them, password included.
        let stored = profile.connectAutomatically ? profile : ProfileSecrets.strip(profile)
        var configuration: [String: Any] = [TunnelKey.profile: try JSONEncoder().encode(stored)]

        if profile.connectAutomatically, profile.auth.needsPassword,
           let pw = Keychain.password(for: profile.id) {
            configuration[TunnelKey.password] = pw
        }

        proto.providerConfiguration = configuration

        m.protocolConfiguration = proto
        m.localizedDescription = profile.name
        m.isEnabled = true
        m.onDemandRules = profile.connectAutomatically ? [NEOnDemandRuleConnect()] : []
        m.isOnDemandEnabled = wantsOnDemand(profile)

        try await m.saveToPreferences()

        // Saved: from here on the configuration exists and must be tracked,
        // even if the reload below fails
        managers[profile.id] = m

        // The saved configuration has to be reloaded before it can be started
        try await m.loadFromPreferences()
    }

    // The profiles were edited. A profile that connects by itself is started by
    // the system from its saved configuration, so that has to follow the edits
    // (and lose its password again when "connect automatically" is switched
    // off). Coalesced: the editor reports every keystroke.
    func profilesChanged(_ profiles: [VPNProfile]) {
        removeOrphans()

        syncTask?.cancel()
        syncTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 800_000_000)
            guard !Task.isCancelled, let self = self else { return }

            for profile in profiles {
                guard let m = self.managers[profile.id],
                      self.state(for: profile.id) == .disconnected,
                      !self.starting.contains(profile.id) else { continue }

                let config = (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
                let storedPassword = config?[TunnelKey.password] as? String
                let wantedPassword = (profile.connectAutomatically && profile.auth.needsPassword)
                    ? Keychain.password(for: profile.id) : nil
                let wantedProfile = profile.connectAutomatically ? profile : ProfileSecrets.strip(profile)

                // A hand-connected profile is rewritten at its next connect
                // anyway; only what the system may act on by itself matters here
                let autoRelevant = profile.connectAutomatically || m.isOnDemandEnabled || storedPassword != nil
                let differs = Self.storedProfile(of: m) != wantedProfile
                    || storedPassword != wantedPassword
                    || m.isOnDemandEnabled != self.wantsOnDemand(profile)

                if autoRelevant && differs {
                    try? await self.configure(m, for: profile)
                }
            }
        }
    }

    // The profile was deleted: stop its tunnel and remove its configuration
    func remove(profileID id: UUID) {
        if let observer = observers.removeValue(forKey: id) {
            NotificationCenter.default.removeObserver(observer)
        }

        states[id] = nil
        statuses[id] = nil
        errors[id] = nil
        pendingTrusts.removeAll { $0.profile.id == id }
        userStopped.remove(id)

        // A start in flight finds this and undoes its own configuration
        if starting.contains(id) {
            removed.insert(id)
        }

        guard let m = managers.removeValue(forKey: id) else { return }

        Self.discard(m)
    }

    // MARK: - Connect / disconnect

    func connect(_ profile: VPNProfile) {
        let id = profile.id

        // One start at a time per profile: a second click must not create a
        // second configuration
        guard !starting.contains(id), state(for: id) == .disconnected else { return }

        guard profile.isComplete else {
            errors[id] = "Enter the server address, the Virtual Hub name and the user name first."
            return
        }

        errors[id] = nil
        lastError = nil
        userStopped.remove(id)
        pendingTrusts.removeAll { $0.profile.id == id }

        starting.insert(id)
        states[id] = .connecting

        Task {
            // Trust on first use: fetch the server's certificate and ask once
            if profile.serverTrust == .pinned && profile.pinnedServerCertificate == nil {
                statuses[id] = TunnelStatus(text: "Checking the server's identity…")

                let result = await ServerProbe.fetchCertificate(of: profile)

                starting.remove(id)
                states[id] = .disconnected
                statuses[id] = nil

                // Deleted, or switched off, while the probe ran
                guard !removed.contains(id), !userStopped.contains(id) else {
                    removed.remove(id)
                    return
                }

                switch result {
                case .success(let der):
                    pendingTrusts.append(PendingTrust(profile: profile, certificate: der,
                                                      fingerprint: ServerProbe.fingerprint(of: der)))
                case .failure(let error):
                    errors[id] = error.localizedDescription
                }
                return
            }

            await start(profile)
        }
    }

    func dismiss(_ pending: PendingTrust) {
        pendingTrusts.removeAll { $0.id == pending.id }
    }

    // The user accepted the certificate shown for a pending connection
    func trustAndConnect(_ pending: PendingTrust, store: ProfileStore) {
        dismiss(pending)

        // The profile as it is now: it may have been edited, or deleted, while
        // the question was on screen
        let id = pending.profile.id
        guard var profile = store.profiles.first(where: { $0.id == id }),
              !starting.contains(id), state(for: id) == .disconnected else { return }

        profile.pinnedServerCertificate = pending.certificate
        store.update(profile)

        starting.insert(id)
        states[id] = .connecting

        Task { await start(profile) }
    }

    // Caller has put the profile into `starting`
    private func start(_ profile: VPNProfile) async {
        let id = profile.id
        let m = managers[id] ?? NETunnelProviderManager()

        defer {
            starting.remove(id)
            removed.remove(id)
        }

        do {
            if m.connection.status != .disconnected && m.connection.status != .invalid {
                m.connection.stopVPNTunnel()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }

            try await configure(m, for: profile)

            // Deleted while the configuration was being saved
            if removed.contains(id) {
                managers[id] = nil
                states[id] = nil
                Self.discard(m)
                return
            }

            // Switched off again before the tunnel was started
            if userStopped.contains(id) {
                states[id] = .disconnected
                return
            }

            observe(m, id: id)

            var options: [String: NSObject] = [:]
            if profile.auth.needsPassword, let pw = Keychain.password(for: id) {
                options[TunnelKey.password] = pw as NSString
            }
            if let secrets = try? JSONEncoder().encode(ProfileSecrets(of: profile)) {
                options[TunnelKey.secrets] = secrets as NSData
            }

            try m.connection.startVPNTunnel(options: options)
        } catch {
            states[id] = .disconnected
            errors[id] = Self.describe(error)
        }
    }

    func disconnect(_ id: UUID) {
        // Remembered also when there is nothing to stop yet (a start in flight)
        userStopped.insert(id)

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

        // Between the click and the system's first report the configuration is
        // still "disconnected"; the switch must not fall back meanwhile
        if new == .disconnected && starting.contains(id) {
            return
        }

        states[id] = new

        if new == .connected {
            errors[id] = nil
        }

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

        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollStatus() }
        }
        // Common modes: keep updating while the menu bar panel is open
        RunLoop.main.add(timer, forMode: .common)
        pollTimer = timer

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
            self.lastError = nil
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

        // 0 is "no session"
        guard started != 0 else {
            return .failure(ProbeError(errorDescription: String(cString: err)))
        }

        let session = started

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
