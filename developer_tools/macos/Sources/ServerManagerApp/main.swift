import SwiftUI
import AppKit
import SoftEtherMacShared

@main
struct SoftEtherVPNServerManagerAppMain: App {
    @StateObject private var vm = ServerManagerViewModel()
    @StateObject private var lang = LanguageManager.shared
    var body: some Scene {
        WindowGroup(I18N.t("app.server.title")) {
            ServerManagerView().environmentObject(vm).environmentObject(lang).frame(minWidth: 1400, minHeight: 860)
        }
    }
}

@MainActor
final class ServerManagerViewModel: ObservableObject {
    @Published var vpncmdPath: String = "/opt/homebrew/bin/vpncmd"
    @Published var host: String = "127.0.0.1"
    @Published var portText: String = "5555"
    @Published var password: String = ""
    @Published var hubName: String = "DEFAULT"
    @Published var output: String = ""

    @Published var hubs: [NamedRow] = []
    @Published var users: [NamedRow] = []
    @Published var sessions: [NamedRow] = []

    @Published var selectedHubName: String = ""
    @Published var selectedUserName: String = ""
    @Published var selectedSessionNames: Set<String> = []

    @Published var newHubName: String = ""
    @Published var newHubPassword: String = ""
    @Published var newHubPasswordForSelected: String = ""

    @Published var newUserName: String = ""
    @Published var newUserPassword: String = ""
    @Published var newPasswordForSelectedUser: String = ""

    @Published var filterHub: String = ""
    @Published var filterUser: String = ""
    @Published var filterSession: String = ""

    @Published var logFiles: [NamedRow] = []
    @Published var selectedLogName: String = ""
    @Published var downloadLogRemotePath: String = ""
    @Published var downloadLogLocalPath: String = ""

    @Published var caRows: [NamedRow] = []
    @Published var selectedCaKey: String = ""

    private var cli: SoftEtherCLI { SoftEtherCLI(vpncmdPath: vpncmdPath) }
    private var port: Int { Int(portText) ?? 5555 }

    var filteredSessions: [NamedRow] {
        filterSession.isEmpty ? sessions : sessions.filter { $0.values.values.joined(separator: " ").localizedCaseInsensitiveContains(filterSession) }
    }

    var selectedHub: NamedRow? { hubs.first(where: { $0.name == selectedHubName }) }
    var selectedUser: NamedRow? { users.first(where: { $0.name == selectedUserName }) }

    private func runServer(_ cmd: [String]) throws -> String {
        try cli.runServerCommand(host: host, port: port, password: password, cmd: cmd)
    }

    func healthCheck() {
        action {
            var issues: [String] = []
            if !FileManager.default.isExecutableFile(atPath: vpncmdPath) { issues.append(String(format: I18N.t("msg.vpncmd.not_executable"), vpncmdPath)) }
            do { _ = try runServer(["ServerStatusGet"]) } catch { issues.append(error.localizedDescription) }
            do { _ = try runServer(["HubList"]) } catch { issues.append(error.localizedDescription) }
            if issues.isEmpty { return I18N.t("msg.health.ok") }
            return I18N.t("msg.health.fail") + "\n- " + issues.joined(separator: "\n- ")
        }
    }

    func status() { action { try runServer(["ServerStatusGet"]) } }

    func loadHubs() {
        action {
            let txt = try runServer(["HubList"])
            hubs = VpnCmdParser.parseRows(txt, preferredNameKeys: ["Virtual Hub Name", "HubName", "Name"])
            if selectedHubName.isEmpty { selectedHubName = hubs.first?.name ?? "" }
            return txt
        }
    }

    func loadUsers() {
        action {
            let txt = try cli.runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["UserList"])
            users = VpnCmdParser.parseRows(txt, preferredNameKeys: ["User Name", "UserName", "Name"])
            if selectedUserName.isEmpty { selectedUserName = users.first?.name ?? "" }
            return txt
        }
    }

    func loadSessions() {
        action {
            let txt = try cli.runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["SessionList"])
            sessions = VpnCmdParser.parseRows(txt, preferredNameKeys: ["Session Name", "Name"])
            selectedSessionNames = []
            return txt
        }
    }

    func createHub() {
        guard !newHubName.isEmpty else { return }
        action {
            try cli.createHub(host: host, port: port, password: password, hubName: newHubName, hubPassword: newHubPassword)
            loadHubs()
            return String(format: I18N.t("msg.created.hub"), newHubName)
        }
    }

    func deleteSelectedHub() {
        guard !selectedHubName.isEmpty else { return }
        action {
            try cli.deleteHub(host: host, port: port, password: password, hubName: selectedHubName)
            loadHubs()
            return String(format: I18N.t("msg.deleted.hub"), selectedHubName)
        }
    }

    func setSelectedHubPassword() {
        guard !selectedHubName.isEmpty, !newHubPasswordForSelected.isEmpty else { return }
        action {
            try cli.setHubPassword(host: host, port: port, password: password, hubName: selectedHubName, newPassword: newHubPasswordForSelected)
            return String(format: I18N.t("msg.updated.hub_password"), selectedHubName)
        }
    }

    func createUser() {
        guard !newUserName.isEmpty, !hubName.isEmpty else { return }
        action {
            try cli.createUser(host: host, port: port, password: password, hubName: hubName, userName: newUserName, userPassword: newUserPassword)
            loadUsers()
            return String(format: I18N.t("msg.created.user"), newUserName)
        }
    }

    func deleteSelectedUser() {
        guard !selectedUserName.isEmpty, !hubName.isEmpty else { return }
        action {
            try cli.deleteUser(host: host, port: port, password: password, hubName: hubName, userName: selectedUserName)
            loadUsers()
            return String(format: I18N.t("msg.deleted.user"), selectedUserName)
        }
    }

    func setSelectedUserPassword() {
        guard !selectedUserName.isEmpty, !newPasswordForSelectedUser.isEmpty, !hubName.isEmpty else { return }
        action {
            try cli.setUserPassword(host: host, port: port, password: password, hubName: hubName, userName: selectedUserName, newPassword: newPasswordForSelectedUser)
            return String(format: I18N.t("msg.updated.user_password"), selectedUserName)
        }
    }

    func disconnectSelectedSessions() {
        guard !selectedSessionNames.isEmpty else { return }
        action {
            for name in selectedSessionNames {
                try cli.disconnectSession(host: host, port: port, password: password, hubName: hubName, sessionName: name)
            }
            loadSessions()
            return String(format: I18N.t("msg.disconnected.sessions"), selectedSessionNames.count)
        }
    }

    func loadLogFiles() {
        action {
            let txt = try runServer(["LogFileList"])
            logFiles = VpnCmdParser.parseRows(txt, preferredNameKeys: ["Name", "Log File Name", "Filename"])
            selectedLogName = logFiles.first?.name ?? ""
            return txt
        }
    }

    func downloadLogFile() {
        guard !downloadLogRemotePath.isEmpty else { return }
        if downloadLogLocalPath.isEmpty {
            let panel = NSSavePanel()
            panel.nameFieldStringValue = URL(fileURLWithPath: downloadLogRemotePath).lastPathComponent
            guard panel.runModal() == .OK, let url = panel.url else { return }
            downloadLogLocalPath = url.path
        }
        action {
            let txt = try runServer(["LogFileSave", downloadLogRemotePath, downloadLogLocalPath])
            return txt
        }
    }

    func loadCa() {
        action {
            caRows = try cli.listCa(host: host, port: port, password: password, hubName: hubName)
            selectedCaKey = caRows.first?.name ?? ""
            return String(format: I18N.t("msg.loaded.ca"), caRows.count)
        }
    }

    func addCa() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        action {
            try cli.addCa(host: host, port: port, password: password, hubName: hubName, certPath: url.path)
            loadCa()
            return String(format: I18N.t("msg.added.ca"), url.path)
        }
    }

    func deleteSelectedCa() {
        guard !selectedCaKey.isEmpty else { return }
        action {
            try cli.deleteCa(host: host, port: port, password: password, hubName: hubName, key: selectedCaKey)
            loadCa()
            return String(format: I18N.t("msg.deleted.ca_key"), selectedCaKey)
        }
    }

    func checkServerCertificate() {
        action { try cli.checkServerCert(host: host, port: port) }
    }

    private func action(_ block: () throws -> String) {
        do { output = try block() } catch {
            output = I18N.t("msg.action.failed") + ": " + I18N.explainVpnCmdError(error.localizedDescription)
        }
    }
}

struct ServerManagerView: View {
    @EnvironmentObject var vm: ServerManagerViewModel
    @EnvironmentObject var lang: LanguageManager

    var body: some View {
        VStack(spacing: 10) {
            GroupBox(I18N.t("section.server_connection")) {
                HStack {
                    TextField(I18N.t("label.vpncmd"), text: $vm.vpncmdPath)
                    TextField(I18N.t("field.host"), text: $vm.host).frame(width: 150)
                    TextField(I18N.t("field.port"), text: $vm.portText).frame(width: 80)
                    TextField(I18N.t("field.hub"), text: $vm.hubName).frame(width: 150)
                    SecureField(I18N.t("field.password"), text: $vm.password).frame(width: 200)
                    Picker(lang.t("label.language"), selection: $lang.languageCode) {
                        ForEach(lang.supportedLanguages, id: \.self) { code in
                            Text(lang.languageDisplayName(code)).tag(code)
                        }
                    }
                    .frame(width: 170)
                    Button(I18N.t("btn.use_system")) { lang.useSystemLanguage() }
                    Button(I18N.t("btn.use_english")) { lang.useEnglishLanguage() }
                    Button(I18N.t("btn.health_check")) { vm.healthCheck() }
                    Button(I18N.t("btn.status")) { vm.status() }
                }
            }

            HSplitView {
                VStack(alignment: .leading, spacing: 8) {
                    GroupBox(I18N.t("section.hubs")) {
                        VStack {
                            HStack { Button(I18N.t("btn.reload")) { vm.loadHubs() } }
                            HStack { TextField(I18N.t("field.new_hub"), text: $vm.newHubName); SecureField(I18N.t("field.hub_password"), text: $vm.newHubPassword); Button(I18N.t("btn.create")) { vm.createHub() } }
                            HStack { SecureField(I18N.t("field.set_selected_hub_password"), text: $vm.newHubPasswordForSelected); Button(I18N.t("btn.apply")) { vm.setSelectedHubPassword() }; Button(I18N.t("btn.delete")) { vm.deleteSelectedHub() } }
                            SortableRowTable(title: I18N.t("section.hub_list"), rows: vm.hubs, preferredNameKeys: ["Virtual Hub Name", "HubName", "Name"], selectedName: $vm.selectedHubName, filterText: $vm.filterHub)
                        }
                    }

                    GroupBox(I18N.t("section.users")) {
                        VStack {
                            HStack { Button(I18N.t("btn.reload")) { vm.loadUsers() } }
                            HStack { TextField(I18N.t("field.new_user"), text: $vm.newUserName); SecureField(I18N.t("field.user_password"), text: $vm.newUserPassword); Button(I18N.t("btn.create")) { vm.createUser() } }
                            HStack { SecureField(I18N.t("field.set_selected_user_password"), text: $vm.newPasswordForSelectedUser); Button(I18N.t("btn.apply")) { vm.setSelectedUserPassword() }; Button(I18N.t("btn.delete")) { vm.deleteSelectedUser() } }
                            SortableRowTable(title: I18N.t("section.user_list"), rows: vm.users, preferredNameKeys: ["User Name", "UserName", "Name"], selectedName: $vm.selectedUserName, filterText: $vm.filterUser)
                        }
                    }
                }
                .frame(minWidth: 460)

                VStack(alignment: .leading, spacing: 8) {
                    GroupBox(I18N.t("section.sessions")) {
                        VStack {
                            HStack { TextField(I18N.t("field.filter_sessions"), text: $vm.filterSession); Button(I18N.t("btn.reload")) { vm.loadSessions() }; Button(I18N.t("btn.disconnect_selected")) { vm.disconnectSelectedSessions() } }
                            List(vm.filteredSessions, id: \.id, selection: $vm.selectedSessionNames) { row in
                                Text(row.name).tag(row.name)
                            }
                        }
                    }

                    GroupBox(I18N.t("section.logs")) {
                        VStack(alignment: .leading) {
                            HStack { Button(I18N.t("btn.reload_logs")) { vm.loadLogFiles() } }
                            List(vm.logFiles, id: \.id, selection: $vm.selectedLogName) { row in
                                Text(row.name).tag(row.name)
                            }
                            HStack {
                                TextField(I18N.t("field.remote_log"), text: $vm.downloadLogRemotePath)
                                TextField(I18N.t("field.local_log"), text: $vm.downloadLogLocalPath)
                                Button(I18N.t("btn.download")) { vm.downloadLogFile() }
                            }
                        }
                    }

                    GroupBox(I18N.t("section.cert_ca")) {
                        VStack(alignment: .leading) {
                            HStack {
                                Button(I18N.t("btn.reload_ca")) { vm.loadCa() }
                                Button(I18N.t("btn.add_ca")) { vm.addCa() }
                                Button(I18N.t("btn.delete_selected_ca")) { vm.deleteSelectedCa() }
                                Button(I18N.t("btn.check_server_cert")) { vm.checkServerCertificate() }
                            }
                            List(vm.caRows, id: \.id, selection: $vm.selectedCaKey) { row in
                                Text(row.name).tag(row.name)
                            }
                        }
                    }

                    GroupBox(I18N.t("section.details")) {
                        HSplitView {
                            KeyValueView(title: "Hub", values: vm.selectedHub?.values ?? [:])
                            KeyValueView(title: "User", values: vm.selectedUser?.values ?? [:])
                        }
                        .frame(minHeight: 180)
                    }

                    GroupBox(I18N.t("section.output")) {
                        TextEditor(text: $vm.output).font(.system(.caption, design: .monospaced)).frame(minHeight: 220)
                    }
                }
            }
        }
        .padding(10)
        .toolbar {
            ToolbarItemGroup {
                Button(I18N.t("btn.health_check")) { vm.healthCheck() }
                Button(I18N.t("btn.reload_hubs")) { vm.loadHubs() }
                Button(I18N.t("btn.reload_users")) { vm.loadUsers() }
                Button(I18N.t("btn.reload_sessions")) { vm.loadSessions() }
            }
        }
    }
}

struct KeyValueView: View {
    let title: String
    let values: [String: String]

    var body: some View {
        VStack(alignment: .leading) {
            Text(title).font(.headline)
            ScrollView {
                VStack(alignment: .leading) {
                    ForEach(values.keys.sorted(), id: \.self) { k in
                        Text("\(k): \(values[k] ?? "")").font(.system(.caption, design: .monospaced))
                    }
                }
            }
        }
        .padding(6)
    }
}
