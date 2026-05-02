import SwiftUI
import AppKit
import SoftEtherMacShared

@main
struct SoftEtherVPNClientAppMain: App {
    @StateObject private var vm = ClientViewModel()
    @StateObject private var lang = LanguageManager.shared
    var body: some Scene {
        WindowGroup(I18N.t("app.client.title")) {
            ClientView().environmentObject(vm).environmentObject(lang).frame(minWidth: 1300, minHeight: 820)
        }
    }
}

@MainActor
final class ClientViewModel: ObservableObject {
    @Published var accounts: [ClientAccount] = []
    @Published var selectedAccountName: String = ""
    @Published var output: String = ""
    @Published var vpncmdPath: String = "/opt/homebrew/bin/vpncmd"
    @Published var filterText: String = ""

    @Published var newName: String = ""
    @Published var newHost: String = "127.0.0.1"
    @Published var newPort: String = "443"
    @Published var newHub: String = "DEFAULT"
    @Published var newUser: String = ""

    @Published var renameTo: String = ""
    @Published var setHost: String = ""
    @Published var setPort: String = "443"

    private var cli: SoftEtherCLI { SoftEtherCLI(vpncmdPath: vpncmdPath) }

    var filteredAccounts: [ClientAccount] {
        if filterText.isEmpty { return accounts }
        return accounts.filter { a in
            a.name.localizedCaseInsensitiveContains(filterText)
            || a.status.localizedCaseInsensitiveContains(filterText)
            || a.server.localizedCaseInsensitiveContains(filterText)
            || a.values.values.joined(separator: " ").localizedCaseInsensitiveContains(filterText)
        }
    }

    var selectedAccount: ClientAccount? {
        accounts.first(where: { $0.name == selectedAccountName })
    }

    func refresh() {
        run {
            accounts = try cli.listClientAccountsStructured()
            if selectedAccountName.isEmpty { selectedAccountName = accounts.first?.name ?? "" }
            return String(format: I18N.t("msg.loaded.accounts"), accounts.count)
        }
    }

    func healthCheck() {
        run {
            var issues: [String] = []
            if !FileManager.default.isExecutableFile(atPath: vpncmdPath) {
                issues.append(String(format: I18N.t("msg.vpncmd.not_executable"), vpncmdPath))
            }
            do { _ = try cli.runClientCommand(["NicList"]) } catch { issues.append(error.localizedDescription) }
            do { _ = try cli.runClientCommand(["AccountList"]) } catch { issues.append(error.localizedDescription) }
            if issues.isEmpty { return I18N.t("msg.health.ok") }
            return I18N.t("msg.health.fail") + "\n- " + issues.joined(separator: "\n- ")
        }
    }

    func createAccount() {
        guard let p = Int(newPort), !newName.isEmpty, !newUser.isEmpty else { return }
        run {
            try cli.createAccount(name: newName, host: newHost, port: p, hub: newHub, user: newUser)
            refresh()
            return String(format: I18N.t("msg.created.account"), newName)
        }
    }

    func connect() { onSelected { try cli.connect(accountName: $0); return String(format: I18N.t("msg.connected.account"), $0) } }
    func disconnect() { onSelected { try cli.disconnect(accountName: $0); return String(format: I18N.t("msg.disconnected.account"), $0) } }
    func status() { onSelected { try cli.accountStatus(accountName: $0) } }
    func delete() { onSelected { try cli.deleteAccount(accountName: $0); refresh(); return String(format: I18N.t("msg.deleted.account"), $0) } }

    func rename() {
        onSelected { name in
            guard !renameTo.isEmpty else { return I18N.t("msg.rename_target_empty") }
            try cli.renameAccount(oldName: name, newName: renameTo)
            refresh()
            return String(format: I18N.t("msg.renamed.account"), name, renameTo)
        }
    }

    func editServer() {
        onSelected { name in
            guard let p = Int(setPort), !setHost.isEmpty else { return I18N.t("msg.invalid_host_port") }
            try cli.setAccountHostPort(accountName: name, host: setHost, port: p)
            refresh()
            return String(format: I18N.t("msg.updated.server.account"), name)
        }
    }

    func importAccount() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        run {
            try cli.importAccount(path: url.path)
            refresh()
            return String(format: I18N.t("msg.imported.account_file"), url.path)
        }
    }

    func exportAccount() {
        onSelected { name in
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "\(name).vpn"
            guard panel.runModal() == .OK, let url = panel.url else { return I18N.t("msg.export_cancelled") }
            try cli.exportAccount(accountName: name, path: url.path)
            return String(format: I18N.t("msg.exported.account_to"), name, url.path)
        }
    }

    private func run(_ op: () throws -> String) {
        do { output = try op() } catch {
            output = I18N.t("msg.action.failed") + ": " + I18N.explainVpnCmdError(error.localizedDescription)
        }
    }
    private func onSelected(_ op: (String) throws -> String) {
        guard !selectedAccountName.isEmpty else { return }
        run { try op(selectedAccountName) }
    }
}

struct ClientView: View {
    @EnvironmentObject var vm: ClientViewModel
    @EnvironmentObject var lang: LanguageManager

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Text(I18N.t("label.vpncmd"))
                TextField("/opt/homebrew/bin/vpncmd", text: $vm.vpncmdPath)
                TextField(I18N.t("label.filter"), text: $vm.filterText).frame(width: 240)
                Picker(lang.t("label.language"), selection: $lang.languageCode) {
                    ForEach(lang.supportedLanguages, id: \.self) { code in
                        Text(lang.languageDisplayName(code)).tag(code)
                    }
                }
                .frame(width: 170)
                Button(I18N.t("btn.use_system")) { lang.useSystemLanguage() }
                Button(I18N.t("btn.use_english")) { lang.useEnglishLanguage() }
                Button(I18N.t("btn.health_check")) { vm.healthCheck() }
                Button(I18N.t("btn.refresh")) { vm.refresh() }
            }

            HSplitView {
                VStack(alignment: .leading) {
                    Text(I18N.t("section.accounts")).font(.headline)
                    List(vm.filteredAccounts, id: \.name, selection: $vm.selectedAccountName) { a in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(a.name).font(.headline)
                                Spacer()
                                Text(a.status)
                                Text(a.server)
                            }
                            .font(.system(.body, design: .monospaced))
                        }
                        .contextMenu {
                            Button(I18N.t("btn.connect")) { vm.selectedAccountName = a.name; vm.connect() }
                            Button(I18N.t("btn.disconnect")) { vm.selectedAccountName = a.name; vm.disconnect() }
                            Button(I18N.t("btn.status")) { vm.selectedAccountName = a.name; vm.status() }
                            Divider()
                            Button(I18N.t("btn.export")) { vm.selectedAccountName = a.name; vm.exportAccount() }
                            Button(I18N.t("btn.delete"), role: .destructive) { vm.selectedAccountName = a.name; vm.delete() }
                        }
                    }
                }
                .padding(8)

                VStack(alignment: .leading, spacing: 10) {
                    GroupBox(I18N.t("section.quick_actions")) {
                        HStack {
                            Button(I18N.t("btn.connect")) { vm.connect() }
                            Button(I18N.t("btn.disconnect")) { vm.disconnect() }
                            Button(I18N.t("btn.status")) { vm.status() }
                            Button(I18N.t("btn.import")) { vm.importAccount() }
                            Button(I18N.t("btn.export")) { vm.exportAccount() }
                            Button(I18N.t("btn.delete")) { vm.delete() }
                        }
                    }

                    GroupBox(I18N.t("section.create_account")) {
                        HStack {
                            TextField(I18N.t("field.name"), text: $vm.newName)
                            TextField(I18N.t("field.host"), text: $vm.newHost)
                            TextField(I18N.t("field.port"), text: $vm.newPort).frame(width: 80)
                            TextField(I18N.t("field.hub"), text: $vm.newHub).frame(width: 140)
                            TextField(I18N.t("field.username"), text: $vm.newUser)
                            Button(I18N.t("btn.create")) { vm.createAccount() }
                        }
                    }

                    GroupBox(I18N.t("section.edit_account")) {
                        VStack {
                            HStack { TextField(I18N.t("field.rename_to"), text: $vm.renameTo); Button(I18N.t("btn.rename")) { vm.rename() } }
                            HStack { TextField(I18N.t("field.set_host"), text: $vm.setHost); TextField(I18N.t("field.set_port"), text: $vm.setPort).frame(width: 90); Button(I18N.t("btn.apply_host_port")) { vm.editServer() } }
                        }
                    }

                    GroupBox(I18N.t("section.selected_details")) {
                        ScrollView {
                            let detail = vm.selectedAccount?.values ?? [:]
                            VStack(alignment: .leading) {
                                ForEach(detail.keys.sorted(), id: \.self) { k in
                                    Text("\(k): \(detail[k] ?? "")").font(.system(.caption, design: .monospaced))
                                }
                            }
                        }
                        .frame(minHeight: 180)
                    }

                    GroupBox(I18N.t("section.output")) {
                        TextEditor(text: $vm.output).font(.system(.caption, design: .monospaced)).frame(minHeight: 220)
                    }
                }
                .padding(8)
                .frame(minWidth: 620)
            }
        }
        .padding(10)
        .toolbar {
            ToolbarItemGroup {
                Button(I18N.t("btn.connect")) { vm.connect() }
                Button(I18N.t("btn.disconnect")) { vm.disconnect() }
                Button(I18N.t("btn.health_check")) { vm.healthCheck() }
                Button(I18N.t("btn.refresh")) { vm.refresh() }
            }
        }
        .onAppear { vm.refresh() }
    }
}
