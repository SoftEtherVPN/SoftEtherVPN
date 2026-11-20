// SoftEther VPN for macOS - packet tunnel provider.
//
// Runs the SoftEther session in-process through the C bridge and exchanges raw
// IP packets with it over the bridge's datagram descriptor. Which networks and
// DNS names use the tunnel is decided by se_make_plan (Bridge/se_plan.c, unit
// tested); this file only maps that plan onto NEPacketTunnelNetworkSettings.

import Foundation
import NetworkExtension
import os.log

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "org.softether.vpnclient.macos", category: "tunnel")

    // Everything below is touched only on this queue
    private let queue = DispatchQueue(label: "org.softether.vpnclient.macos.tunnel")

    private var profile = VPNProfile()
    private var password: String?
    private var session: se_session?        // handle of the C bridge; never 0
    private var readSource: DispatchSourceRead?
    private var monitor: DispatchSourceTimer?
    private var stopping = false
    private var reconnecting = false
    private var lastStatus = TunnelStatus()

    // The descriptor outbound packets are written to; read from the
    // packetFlow callback thread, hence its own lock
    private let fdLock = NSLock()
    private var outboundFD: Int32 = -1
    private var outboundLoopRunning = false     // guarded by fdLock
    private var dropIPv6 = false                // guarded by fdLock

    private static let connectTimeout: TimeInterval = 60
    private static let reconnectDelays: [TimeInterval] = [1, 2, 5, 10, 20, 30]

    // Errors a retry cannot fix
    private static let fatalCodes: Set<Int> = [
        Int(SE_ERR_AUTH_FAILED), Int(SE_ERR_HUB_NOT_FOUND), Int(SE_ERR_CERT_NOT_TRUSTED),
        Int(SE_ERR_HOSTNAME_MISMATCH), Int(SE_ERR_SERVER_CERT_EXPIRES),
    ]

    // MARK: - NEPacketTunnelProvider

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        queue.async {
            self.stopping = false

            guard
                let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
                let json = proto.providerConfiguration?[TunnelKey.profile] as? Data,
                let profile = try? JSONDecoder().decode(VPNProfile.self, from: json)
            else {
                completionHandler(TunnelError.message("The connection settings could not be read.").nsError)
                return
            }

            var merged = profile

            // Keys and saved hashes are stripped from the stored configuration
            // unless the profile connects by itself; the app hands them over
            // with the start request instead
            if let data = options?[TunnelKey.secrets] as? Data,
               let secrets = try? JSONDecoder().decode(ProfileSecrets.self, from: data) {
                secrets.apply(to: &merged)
            }

            self.profile = merged
            // From the app when the user connects; from the saved configuration
            // when the system starts the tunnel on demand
            self.password = (options?[TunnelKey.password] as? String)
                ?? (proto.providerConfiguration?[TunnelKey.password] as? String)

            guard Bridge.start() else {
                completionHandler(TunnelError.message("The VPN core could not be started.").nsError)
                return
            }

            self.connect { error in
                if error != nil {
                    self.teardownSession()
                }
                completionHandler(portable(error))
                if error == nil && !self.stopping {
                    self.startMonitor()
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.stopping = true
            self.monitor?.cancel()
            self.monitor = nil
            self.teardownSession()
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        queue.async {
            self.refreshTraffic()
            completionHandler?(try? JSONEncoder().encode(self.lastStatus))
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    // The connection to the server does not survive sleep, and the core would
    // only notice after its keep-alive timeout: reconnect right away instead
    // of leaving the routes pointing into a dead tunnel
    override func wake() {
        queue.async {
            // Only an established tunnel (the monitor runs): a start that is
            // still in progress has its own completion to honor
            guard self.session != nil, self.monitor != nil, !self.stopping, !self.reconnecting else { return }

            self.reconnecting = true
            self.reasserting = true
            self.teardownSession()
            self.lastStatus.text = "Reconnecting..."
            self.reconnect(attempt: 0)
        }
    }

    // MARK: - Session

    // Dial, wait for the hub's IP configuration and apply the network
    // settings. The completion runs on the queue.
    private func connect(completion: @escaping (Error?) -> Void) {
        let bridgeProfile = BridgeProfile(profile, password: password)
        var err = [CChar](repeating: 0, count: 256)
        var p = bridgeProfile.value

        // The se_profile points into bridgeProfile's buffers
        let started = withExtendedLifetime(bridgeProfile) {
            se_connect(&p, &err, err.count)
        }

        // 0 is "no session"
        guard started != 0 else {
            completion(TunnelError.message(String(cString: err)))
            return
        }

        let s = started

        session = s
        waitForConfiguration(deadline: Date().addingTimeInterval(Self.connectTimeout), completion: completion)
    }

    private func waitForConfiguration(deadline: Date, completion: @escaping (Error?) -> Void) {
        guard let s = session, !stopping else {
            completion(TunnelError.message("Cancelled."))
            return
        }

        let status = se_get_status(s)
        lastStatus.text = Bridge.statusText(s)

        if status == Int32(SE_STATUS_CONNECTED) {
            applySettings(completion: completion)
        } else if status == Int32(SE_STATUS_CONNECTING) && Date() < deadline {
            queue.asyncAfter(deadline: .now() + 0.1) {
                self.waitForConfiguration(deadline: deadline, completion: completion)
            }
        } else if status == Int32(SE_STATUS_CONNECTING) {
            completion(TunnelError.message("The VPN server did not answer in time."))
        } else {
            completion(TunnelError.session(code: Int(se_get_error(s)), text: Bridge.statusText(s)))
        }
    }

    private func teardownSession() {
        readSource?.cancel()
        readSource = nil

        fdLock.lock()
        outboundFD = -1
        fdLock.unlock()

        if let s = session {
            session = nil
            se_disconnect(s)    // closes the packet descriptor
        }

        lastStatus = TunnelStatus(text: lastStatus.text)
    }

    // MARK: - Network settings

    private func applySettings(completion: @escaping (Error?) -> Void) {
        guard let s = session else {
            completion(TunnelError.message("Cancelled."))
            return
        }

        var v4 = se_ipv4_config()
        var v6 = se_ipv6_config()
        let hasV4 = se_get_ipv4_config(s, &v4) == 1
        let hasV6 = se_get_ipv6_config(s, &v6) == 1 && !cString(v6.address).isEmpty

        // se_plan is large; keep it on the heap and hand the C accessors a pointer
        let plan = UnsafeMutablePointer<se_plan>.allocate(capacity: 1)
        plan.initialize(to: se_plan())
        defer { plan.deallocate() }

        var err = [CChar](repeating: 0, count: 256)
        let profile = self.profile

        let made: Int32 = profile.networks.withCString { networks -> Int32 in
            profile.dnsServers.withCString { dnsServers -> Int32 in
                profile.dnsDomains.withCString { dnsDomains -> Int32 in
                    var policy = se_policy()
                    policy.tunnel_mode = Int32(profile.tunnelMode.rawValue)
                    policy.networks = networks
                    policy.use_pushed_routes = profile.usePushedRoutes ? 1 : 0
                    policy.block_ipv6 = profile.blockIPv6Leaks ? 1 : 0
                    policy.dns_mode = Int32(profile.dnsMode.rawValue)
                    policy.dns_servers = dnsServers
                    policy.dns_domains = dnsDomains

                    return withUnsafePointer(to: v4) { v4p -> Int32 in
                        withUnsafePointer(to: v6) { v6p -> Int32 in
                            se_make_plan(&policy, hasV4 ? v4p : nil, hasV6 ? v6p : nil, plan, &err, err.count)
                        }
                    }
                }
            }
        }

        guard made == 1 else {
            completion(TunnelError.message(String(cString: err)))
            return
        }

        let server = Bridge.serverAddress(s) ?? profile.host
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: server)
        settings.mtu = 1500

        var routed: [String] = []
        var bypassed: [String] = []
        var included4: [NEIPv4Route] = []
        var excluded4: [NEIPv4Route] = []
        var included6: [NEIPv6Route] = []
        var excluded6: [NEIPv6Route] = []

        func collect(_ get: (Int32) -> UnsafePointer<se_net>?, _ count: Int32,
                     into r4: inout [NEIPv4Route], _ r6: inout [NEIPv6Route], names: inout [String]) {
            for i in 0..<count {
                guard let net = get(i) else { continue }
                let address = String(cString: se_net_address(net))
                let prefix = Int(net.pointee.prefix_len)

                let family = net.pointee.is_ipv6 != 0 ? "IPv6" : "IPv4"
                names.append(prefix == 0 ? "Everything (\(family))" : "\(address)/\(prefix)")

                if net.pointee.is_ipv6 != 0 {
                    r6.append(prefix == 0 ? NEIPv6Route.default()
                        : NEIPv6Route(destinationAddress: address, networkPrefixLength: NSNumber(value: prefix)))
                } else {
                    r4.append(prefix == 0 ? NEIPv4Route.default()
                        : NEIPv4Route(destinationAddress: address, subnetMask: String(cString: se_net_mask(net))))
                }
            }
        }

        collect({ se_plan_included(plan, $0) }, plan.pointee.num_included,
                into: &included4, &included6, names: &routed)
        collect({ se_plan_excluded(plan, $0) }, plan.pointee.num_excluded,
                into: &excluded4, &excluded6, names: &bypassed)

        if hasV4 {
            let ipv4 = NEIPv4Settings(addresses: [cString(v4.address)], subnetMasks: [cString(v4.mask)])
            ipv4.includedRoutes = included4
            ipv4.excludedRoutes = excluded4
            settings.ipv4Settings = ipv4
        }

        if hasV6 {
            let prefix = v6.prefix_len > 0 ? Int(v6.prefix_len) : 64
            let ipv6 = NEIPv6Settings(addresses: [cString(v6.address)], networkPrefixLengths: [NSNumber(value: prefix)])
            ipv6.includedRoutes = included6
            ipv6.excludedRoutes = excluded6
            settings.ipv6Settings = ipv6
        }

        // The VPN has no IPv6 but everything is to go through it: give the
        // tunnel an address that attracts IPv6, and discard it in the pump
        let blackholeIPv6 = plan.pointee.blackhole_ipv6 != 0 && !hasV6

        if blackholeIPv6 {
            let ipv6 = NEIPv6Settings(addresses: [SE_BLACKHOLE_IPV6],
                                      networkPrefixLengths: [NSNumber(value: SE_BLACKHOLE_IPV6_PREFIX)])
            ipv6.includedRoutes = included6
            ipv6.excludedRoutes = excluded6
            settings.ipv6Settings = ipv6
        }

        // Without IPv6 on the VPN nothing of it may reach the hub, blackhole or
        // not (the interface can still emit link-local chatter)
        fdLock.lock()
        dropIPv6 = !hasV6
        fdLock.unlock()

        var dnsServers: [String] = []
        var matchDomains: [String] = []
        var searchDomains: [String] = []

        for i in 0..<plan.pointee.num_dns_servers {
            if let p = se_plan_dns_server(plan, i) { dnsServers.append(String(cString: p)) }
        }
        for i in 0..<plan.pointee.num_match_domains {
            if let p = se_plan_match_domain(plan, i) { matchDomains.append(String(cString: p)) }
        }
        for i in 0..<plan.pointee.num_search_domains {
            if let p = se_plan_search_domain(plan, i) { searchDomains.append(String(cString: p)) }
        }

        let matchAll = plan.pointee.dns_match_all != 0

        if plan.pointee.dns_enabled != 0 && !dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: dnsServers)

            if matchAll {
                // An empty match domain makes these servers the resolver for
                // every name, also when the tunnel is not the default route
                dns.matchDomains = [""]
            } else {
                // Split DNS: only names under these domains are sent to the
                // VPN's servers; they are not turned into search suffixes
                dns.matchDomains = matchDomains
                dns.matchDomainsNoSearch = true
            }

            if !searchDomains.isEmpty {
                dns.searchDomains = searchDomains
            }

            settings.dnsSettings = dns
        }

        let warnings = String(cString: se_plan_warnings(plan)).split(separator: "\n").map(String.init)
        warnings.forEach { os_log("plan: %{public}@", log: self.log, type: .info, $0) }

        var status = TunnelStatus()
        status.text = "Connected."
        status.connected = true
        status.fullTunnel = plan.pointee.full_tunnel != 0
        status.address = hasV4 ? cString(v4.address) : ""
        status.address6 = hasV6 ? cString(v6.address) : ""
        status.server = server
        status.dnsServers = settings.dnsSettings != nil ? dnsServers : []
        status.dnsDomains = matchAll ? [] : matchDomains
        status.routedNetworks = routed
        status.bypassedNetworks = bypassed
        status.warnings = warnings + (blackholeIPv6
            ? ["This VPN has no IPv6, so IPv6 traffic is blocked while connected."] : [])

        setTunnelNetworkSettings(settings) { error in
            self.queue.async {
                if let error = error {
                    completion(error)
                    return
                }

                guard self.startPacketPump() else {
                    completion(TunnelError.message("The packet channel of the VPN session is not available."))
                    return
                }

                self.lastStatus = status
                completion(nil)
            }
        }
    }

    // MARK: - Packets

    private func startPacketPump() -> Bool {
        guard let s = session else { return false }

        let fd = se_packet_fd(s)
        guard fd >= 0 else { return false }

        // The read source gets a descriptor of its own, closed from its cancel
        // handler as libdispatch requires. The bridge closes its descriptor
        // inside se_disconnect, which may run before the cancellation is done.
        let readFD = dup(fd)
        guard readFD >= 0 else { return false }

        // Non-blocking on our end (the flag is shared by both descriptors): a
        // full queue drops the packet instead of stalling the system's packet
        // flow, which is what a real interface does
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)

        // Only one readPackets request may be outstanding: after a reconnect the
        // request of the previous session is still pending and simply continues
        // with the new descriptor
        fdLock.lock()
        outboundFD = fd
        let startLoop = !outboundLoopRunning
        outboundLoopRunning = true
        fdLock.unlock()

        // VPN -> system
        let source = DispatchSource.makeReadSource(fileDescriptor: readFD, queue: queue)
        var buffer = [UInt8](repeating: 0, count: 65536)

        source.setEventHandler { [weak self] in
            guard let self = self else { return }

            var packets: [Data] = []
            var protocols: [NSNumber] = []

            while packets.count < 128 {
                let n = read(readFD, &buffer, buffer.count)
                if n <= 0 { break }

                let family = (buffer[0] >> 4) == 6 ? AF_INET6 : AF_INET
                packets.append(Data(buffer[0..<n]))
                protocols.append(NSNumber(value: family))
            }

            if !packets.isEmpty {
                self.packetFlow.writePackets(packets, withProtocols: protocols)
            }
        }
        source.setCancelHandler { close(readFD) }
        source.resume()
        readSource = source

        // System -> VPN
        if startLoop {
            readOutboundPackets()
        }

        return true
    }

    private func readOutboundPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }

            // The lock also keeps teardown from closing the descriptor mid-write
            self.fdLock.lock()
            let fd = self.outboundFD
            if fd >= 0 {
                for packet in packets {
                    // An empty datagram would read as "closed" on the other end
                    guard let first = packet.first else { continue }
                    if self.dropIPv6, first >> 4 == 6 {
                        continue
                    }
                    packet.withUnsafeBytes { raw in
                        _ = write(fd, raw.baseAddress, raw.count)
                    }
                }
            } else {
                // No session: drop, and stop until the next one starts the loop
                self.outboundLoopRunning = false
            }
            self.fdLock.unlock()

            if fd >= 0 {
                self.readOutboundPackets()
            }
        }
    }

    // MARK: - Monitoring and reconnection

    private func startMonitor() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in self?.checkSession() }
        timer.resume()
        monitor = timer
    }

    private func refreshTraffic() {
        guard let s = session else { return }

        var traffic = se_traffic()
        if se_get_traffic(s, &traffic) == 1 {
            lastStatus.bytesSent = traffic.bytes_sent
            lastStatus.bytesReceived = traffic.bytes_received
        }
    }

    private func checkSession() {
        guard let s = session, !stopping, !reconnecting else { return }
        guard se_get_status(s) != Int32(SE_STATUS_CONNECTED) else { return }

        let code = Int(se_get_error(s))
        let text = Bridge.statusText(s)
        os_log("session lost: %{public}@", log: log, type: .error, text)

        // Errors a retry cannot fix end the tunnel; anything else is treated as
        // a network interruption
        if Self.fatalCodes.contains(code) {
            stopping = true
            monitor?.cancel()
            monitor = nil
            teardownSession()
            cancelTunnelWithError(TunnelError.session(code: code, text: text).nsError)
            return
        }

        reconnecting = true
        reasserting = true
        teardownSession()
        lastStatus.text = "Reconnecting..."
        reconnect(attempt: 0)
    }

    private func reconnect(attempt: Int) {
        guard !stopping else { return }

        let delays = Self.reconnectDelays
        let delay = delays[min(attempt, delays.count - 1)]

        queue.asyncAfter(deadline: .now() + delay) {
            guard !self.stopping else { return }

            self.connect { error in
                if error == nil {
                    self.reconnecting = false
                    self.reasserting = false
                    return
                }

                self.teardownSession()

                if case TunnelError.session(let code, _)? = error as? TunnelError,
                   Self.fatalCodes.contains(code) {
                    self.stopping = true
                    self.monitor?.cancel()
                    self.monitor = nil
                    self.cancelTunnelWithError(portable(error))
                    return
                }

                self.lastStatus.text = "Reconnecting..."
                self.reconnect(attempt: attempt + 1)
            }
        }
    }
}

enum TunnelError: LocalizedError {
    case message(String)
    case session(code: Int, text: String)

    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        case .session(_, let text): return text
        }
    }

    // The system carries an error from the extension to the app as a plain
    // NSError; a Swift error's description does not survive that, so the text
    // goes into the user info explicitly. The code is SoftEther's error code
    // for a session error, -1 otherwise.
    var nsError: NSError {
        let code: Int
        switch self {
        case .message: code = -1
        case .session(let c, _): code = c
        }

        return NSError(domain: "org.softether.vpnclient.macos.tunnel", code: code,
                       userInfo: [NSLocalizedDescriptionKey: errorDescription ?? "VPN error"])
    }
}

private func portable(_ error: Error?) -> Error? {
    (error as? TunnelError)?.nsError ?? error
}
