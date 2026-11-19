// SoftEther VPN for macOS - menu bar app.

import SwiftUI

@main
@MainActor
struct SoftEtherVPNApp: App {
    @StateObject private var store = ProfileStore()
    @StateObject private var vpn = VPNController()

    var body: some Scene {
        MenuBarExtra {
            MenuContent()
                .environmentObject(store)
                .environmentObject(vpn)
        } label: {
            Image(systemName: menuIcon)
        }
        .menuBarExtraStyle(.window)

        Window("SoftEther VPN Connections", id: "profiles") {
            ProfilesWindow()
                .environmentObject(store)
                .environmentObject(vpn)
                .frame(minWidth: 720, minHeight: 520)
        }
    }

    private var menuIcon: String {
        if vpn.isAnyBusy { return "arrow.triangle.2.circlepath" }
        return vpn.isAnyConnected ? "lock.shield.fill" : "lock.shield"
    }
}

// The panel under the menu bar icon: one switch per connection
@MainActor
struct MenuContent: View {
    @EnvironmentObject private var store: ProfileStore
    @EnvironmentObject private var vpn: VPNController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if vpn.extensionNeedsApproval {
                Label("Allow the network extension in System Settings > General > Login Items & Extensions, then connect again.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if store.profiles.isEmpty {
                Text("No connections yet.")
                    .foregroundStyle(.secondary)
            }

            ForEach(store.profiles) { profile in
                ConnectionRow(profile: profile)
            }

            ForEach(vpn.pendingTrusts) { pending in
                TrustPrompt(pending: pending)
            }

            if let warning = vpn.overlapWarning(among: store.profiles) {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let error = vpn.lastError {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            HStack {
                Button("Connections…") {
                    openWindow(id: "profiles")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 340)
    }
}

@MainActor
struct ConnectionRow: View {
    @EnvironmentObject private var vpn: VPNController
    let profile: VPNProfile

    private var state: VPNController.State { vpn.state(for: profile.id) }
    private var status: TunnelStatus { vpn.status(for: profile.id) }
    private var isActive: Bool { state != .disconnected }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: Binding(
                get: { isActive },
                set: { on in
                    if on { vpn.connect(profile) } else { vpn.disconnect(profile.id) }
                }
            )) {
                VStack(alignment: .leading) {
                    Text(profile.name).font(.headline)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.switch)

            if state == .connected {
                ConnectionDetails(status: status)
            }

            if let error = vpn.errors[profile.id] {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var subtitle: String {
        switch state {
        case .connecting: return status.text.isEmpty ? "Connecting…" : status.text
        case .reconnecting: return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        case .connected: return "Connected · \(status.address)"
        case .disconnected: return profile.host
        }
    }
}

// What the tunnel is actually doing, in plain words
struct ConnectionDetails: View {
    let status: TunnelStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            line("Through the VPN", status.routedNetworks.joined(separator: ", "))
            if !status.bypassedNetworks.isEmpty {
                line("Bypassing the VPN", status.bypassedNetworks.joined(separator: ", "))
            }
            if status.dnsServers.isEmpty {
                line("DNS", "Unchanged")
            } else if status.dnsDomains.isEmpty {
                line("DNS", "All names via \(status.dnsServers.joined(separator: ", "))")
            } else {
                line("DNS", "\(status.dnsDomains.joined(separator: ", ")) via \(status.dnsServers.joined(separator: ", "))")
            }
            line("Traffic", "\(format(status.bytesReceived)) received, \(format(status.bytesSent)) sent")

            ForEach(status.warnings, id: \.self) { warning in
                Label(warning, systemImage: "info.circle")
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    private func line(_ title: String, _ value: String) -> some View {
        Text("\(title): \(value)").fixedSize(horizontal: false, vertical: true)
    }

    private func format(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .binary)
    }
}

// First connection to a server: show its certificate fingerprint once
@MainActor
struct TrustPrompt: View {
    @EnvironmentObject private var store: ProfileStore
    @EnvironmentObject private var vpn: VPNController
    let pending: VPNController.PendingTrust

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("\(pending.profile.name): is this the right server?").font(.headline)
            Text("\(pending.profile.host) identified itself with a certificate that has this SHA-256 fingerprint. Compare it with the one your administrator gave you.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Text(pending.fingerprint)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Cancel") { vpn.dismiss(pending) }
                Spacer()
                Button("Trust and Connect") { vpn.trustAndConnect(pending, store: store) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(10)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}
