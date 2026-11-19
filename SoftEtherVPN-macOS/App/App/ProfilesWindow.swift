// SoftEther VPN for macOS - connection list and editor.

import SwiftUI

@MainActor
struct ProfilesWindow: View {
    @EnvironmentObject private var store: ProfileStore
    @EnvironmentObject private var vpn: VPNController
    @State private var selection: UUID?
    @State private var importing = false
    @State private var importError: String?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                ForEach(store.profiles) { profile in
                    Text(profile.name).tag(profile.id)
                }
            }
            .toolbar {
                ToolbarItemGroup {
                    Button {
                        let profile = VPNProfile()
                        store.update(profile)
                        selection = profile.id
                    } label: {
                        Label("Add", systemImage: "plus")
                    }

                    Button {
                        importing = true
                    } label: {
                        Label("Import .vpn File", systemImage: "square.and.arrow.down")
                    }
                    .help("Import a connection exported by the SoftEther VPN Client for Windows")

                    Button {
                        if let p = store.profiles.first(where: { $0.id == selection }) {
                            vpn.remove(profileID: p.id)
                            store.delete(p)
                            selection = store.profiles.first?.id
                        }
                    } label: {
                        Label("Remove", systemImage: "minus")
                    }
                    .disabled(selection == nil)
                }
            }
        } detail: {
            if let id = selection, store.profiles.contains(where: { $0.id == id }) {
                // Looked up by id on every access: an index-based binding can be
                // read once more after its profile was removed
                ProfileEditor(profile: Binding(
                    get: { store.profiles.first { $0.id == id } ?? VPNProfile() },
                    set: { edited in
                        if store.profiles.contains(where: { $0.id == edited.id }) { store.update(edited) }
                    }
                ))
                .id(id)
            } else {
                Text("Add a connection to get started.")
                    .foregroundStyle(.secondary)
            }
        }
        .onAppear {
            if selection == nil { selection = store.profiles.first?.id }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            guard case .success(let url) = result else { return }
            importFile(url)
        }
        .alert("The file could not be imported", isPresented: Binding(
            get: { importError != nil }, set: { if !$0 { importError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(importError ?? "")
        }
    }

    private func importFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        do {
            let imported = try Bridge.importVPNFile(try Data(contentsOf: url))

            if let password = imported.password {
                Keychain.setPassword(password, for: imported.profile.id)
            }

            store.update(imported.profile)
            selection = imported.profile.id
        } catch {
            importError = error.localizedDescription
        }
    }
}

@MainActor
struct ProfileEditor: View {
    @Binding var profile: VPNProfile
    @State private var password = ""
    @State private var showAdvanced = false

    var body: some View {
        Form {
            Section("Server") {
                TextField("Name", text: $profile.name)
                TextField("Server address", text: $profile.host, prompt: Text("vpn.example.com"))
                TextField("Port", value: $profile.port, format: .number.grouping(.never))
                TextField("Virtual Hub", text: $profile.hub)
            }

            Section("Sign in") {
                Picker("Method", selection: $profile.auth) {
                    ForEach(AuthMethod.allCases) { Text($0.title).tag($0) }
                }

                if profile.auth != .anonymous {
                    TextField("User name", text: $profile.username)
                }

                if profile.auth.needsPassword {
                    SecureField("Password", text: $password,
                                prompt: profile.passwordHash != nil ? Text("Saved in the imported file") : nil)
                        .onChange(of: password) { Keychain.setPassword($0, for: profile.id) }
                }

                if profile.auth == .certificate {
                    FileField(title: "Certificate", data: $profile.clientCertificate)
                    FileField(title: "Private key", data: $profile.clientPrivateKey)
                }
            }

            Section {
                Picker("Send through the VPN", selection: $profile.tunnelMode) {
                    ForEach(TunnelMode.allCases) { Text($0.title).tag($0) }
                }

                if profile.tunnelMode == .includeOnly || profile.tunnelMode == .excludeListed {
                    TextField(profile.tunnelMode == .includeOnly ? "Networks to reach" : "Networks to bypass",
                              text: $profile.networks,
                              prompt: Text("10.0.0.0/8, 192.168.50.0/24"),
                              axis: .vertical)
                        .lineLimit(2...5)
                }

                if profile.tunnelMode == .includeOnly {
                    Toggle("Also use the networks the server announces", isOn: $profile.usePushedRoutes)
                }
            } header: {
                Text("Traffic")
            } footer: {
                Text(trafficHelp)
            }

            Section {
                Picker("Name lookups", selection: $profile.dnsMode) {
                    ForEach(DNSMode.allCases) { Text($0.title).tag($0) }
                }

                if profile.dnsMode == .splitDomains || profile.dnsMode == .automatic {
                    TextField("Domains", text: $profile.dnsDomains,
                              prompt: Text("corp.example.com, intranet.example"), axis: .vertical)
                        .lineLimit(1...4)
                }
            } header: {
                Text("DNS")
            } footer: {
                Text(dnsHelp)
            }

            Section("Security") {
                Picker("Server identity", selection: $profile.serverTrust) {
                    ForEach(ServerTrust.allCases) { Text($0.title).tag($0) }
                }

                if profile.serverTrust == .pinned && profile.pinnedServerCertificate != nil {
                    HStack {
                        Text("Server certificate remembered.")
                        Spacer()
                        Button("Forget") { profile.pinnedServerCertificate = nil }
                    }
                }
            }

            Section {
                Toggle("Connect automatically", isOn: $profile.connectAutomatically)
            } footer: {
                Text("Connects whenever this Mac is online, also after a restart. The password is then stored with the VPN configuration so the system can sign in without this app.")
            }

            DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                TextField("DNS servers (leave empty to use the VPN's)", text: $profile.dnsServers)
                Toggle("Use IPv6 inside the VPN", isOn: $profile.useIPv6)
                Toggle("Block IPv6 when the VPN has none", isOn: $profile.blockIPv6Leaks)

                Picker("Proxy", selection: $profile.proxy) {
                    ForEach(ProxyKind.allCases) { Text($0.title).tag($0) }
                }
                if profile.proxy != .none {
                    TextField("Proxy server", text: $profile.proxyHost)
                    TextField("Proxy port", value: $profile.proxyPort, format: .number.grouping(.never))
                    TextField("Proxy user name", text: $profile.proxyUsername)
                    SecureField("Proxy password", text: $profile.proxyPassword)
                }
                Toggle("Compress traffic", isOn: $profile.useCompression)
                Toggle("Disable UDP acceleration", isOn: $profile.disableUDPAcceleration)
            }
        }
        .formStyle(.grouped)
        .onAppear { password = Keychain.password(for: profile.id) ?? "" }
    }

    private var trafficHelp: String {
        switch profile.tunnelMode {
        case .serverDecides:
            return "The VPN server decides, as with the Windows client. If it announces specific networks, only those go through the VPN. Otherwise, if it provides a default gateway, everything does."
        case .full:
            return "Everything this Mac sends goes through the VPN while it is connected."
        case .includeOnly:
            return "Only the VPN's own network and the networks listed here go through the VPN. Everything else uses your normal connection."
        case .excludeListed:
            return "Everything goes through the VPN except the networks listed here."
        }
    }

    private var dnsHelp: String {
        switch profile.dnsMode {
        case .automatic:
            return "All names are looked up through the VPN when all traffic goes through it. When only some networks do, only the VPN's own domain and the domains listed here are."
        case .allNames:
            return "Every name is looked up by the VPN's DNS servers."
        case .splitDomains:
            return "Only names ending in these domains are looked up by the VPN's DNS servers."
        case .off:
            return "The VPN does not change how names are looked up."
        }
    }
}

// Pick a certificate or key file
struct FileField: View {
    let title: String
    @Binding var data: Data?
    @State private var importing = false

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            Text(data == nil ? "None" : "Loaded").foregroundStyle(.secondary)
            Button("Choose…") { importing = true }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            if case .success(let url) = result {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                data = try? Data(contentsOf: url)
            }
        }
    }
}
