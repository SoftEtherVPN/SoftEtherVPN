import Foundation

public struct SoftEtherCLI {
    public let vpncmdPath: String
    public let serviceBinaryPath: String

    public init(vpncmdPath: String = "/opt/homebrew/bin/vpncmd", serviceBinaryPath: String = "/opt/homebrew/bin/vpnclient") {
        self.vpncmdPath = vpncmdPath
        self.serviceBinaryPath = serviceBinaryPath
    }

    @discardableResult
    public func runVpncmd(arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: vpncmdPath)
        process.arguments = arguments

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        try process.run()
        process.waitUntilExit()

        let output = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let error = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw NSError(domain: "SoftEtherCLI", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: error.isEmpty ? output : error])
        }

        return output
    }

    public func runClientCommand(_ cmd: [String]) throws -> String {
        try runVpncmd(arguments: ["localhost", "/CLIENT", "/CMD"] + cmd)
    }

    public func runServerCommand(host: String, port: Int, password: String, cmd: [String]) throws -> String {
        try runVpncmd(arguments: ["\(host):\(port)", "/SERVER", "/PASSWORD:\(password)", "/CMD"] + cmd)
    }

    public func runHubCommand(host: String, port: Int, password: String, hubName: String, cmd: [String]) throws -> String {
        try runVpncmd(arguments: ["\(host):\(port)", "/SERVER", "/HUB:\(hubName)", "/PASSWORD:\(password)", "/CMD"] + cmd)
    }

    public func listClientAccountsStructured() throws -> [ClientAccount] {
        let output = try runClientCommand(["AccountList"])
        return VpnCmdParser.parseNamedRows(output).map(ClientAccount.from).filter { !$0.name.isEmpty }
    }

    public func createAccount(name: String, host: String, port: Int, hub: String, user: String) throws {
        _ = try runClientCommand(["AccountCreate", name, "/SERVER:\(host):\(port)", "/HUB:\(hub)", "/USERNAME:\(user)", "/NICNAME:VPN"])
    }

    public func connect(accountName: String) throws { _ = try runClientCommand(["AccountConnect", accountName]) }
    public func disconnect(accountName: String) throws { _ = try runClientCommand(["AccountDisconnect", accountName]) }
    public func accountStatus(accountName: String) throws -> String { try runClientCommand(["AccountStatusGet", accountName]) }
    public func deleteAccount(accountName: String) throws { _ = try runClientCommand(["AccountDelete", accountName]) }
    public func renameAccount(oldName: String, newName: String) throws { _ = try runClientCommand(["AccountRename", oldName, "/NEW:\(newName)"]) }
    public func setAccountHostPort(accountName: String, host: String, port: Int) throws { _ = try runClientCommand(["AccountSet", accountName, "/SERVER:\(host)", "/PORT:\(port)"]) }
    public func importAccount(path: String) throws { _ = try runClientCommand(["AccountImport", path]) }
    public func exportAccount(accountName: String, path: String) throws { _ = try runClientCommand(["AccountExport", accountName, path]) }

    public func serverStatus(host: String, port: Int, password: String) throws -> String {
        try runServerCommand(host: host, port: port, password: password, cmd: ["ServerStatusGet"])
    }

    public func createHub(host: String, port: Int, password: String, hubName: String, hubPassword: String) throws {
        _ = try runServerCommand(host: host, port: port, password: password, cmd: ["HubCreate", hubName, "/PASSWORD:\(hubPassword)"])
    }
    public func deleteHub(host: String, port: Int, password: String, hubName: String) throws {
        _ = try runServerCommand(host: host, port: port, password: password, cmd: ["HubDelete", hubName])
    }
    public func setHubPassword(host: String, port: Int, password: String, hubName: String, newPassword: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["SetHubPassword", "/PASSWORD:\(newPassword)"])
    }

    public func createUser(host: String, port: Int, password: String, hubName: String, userName: String, userPassword: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["UserCreate", userName, "/GROUP:none", "/REALNAME:none", "/NOTE:none"])
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["UserPasswordSet", userName, "/PASSWORD:\(userPassword)"])
    }
    public func deleteUser(host: String, port: Int, password: String, hubName: String, userName: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["UserDelete", userName])
    }
    public func setUserPassword(host: String, port: Int, password: String, hubName: String, userName: String, newPassword: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["UserPasswordSet", userName, "/PASSWORD:\(newPassword)"])
    }
    public func disconnectSession(host: String, port: Int, password: String, hubName: String, sessionName: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["SessionDisconnect", sessionName])
    }

    public func listCa(host: String, port: Int, password: String, hubName: String) throws -> [NamedRow] {
        let txt = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["CaList"])
        return VpnCmdParser.parseRows(txt, preferredNameKeys: ["Key", "Name", "Subject"])
    }

    public func addCa(host: String, port: Int, password: String, hubName: String, certPath: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["CaAdd", certPath])
    }

    public func deleteCa(host: String, port: Int, password: String, hubName: String, key: String) throws {
        _ = try runHubCommand(host: host, port: port, password: password, hubName: hubName, cmd: ["CaDelete", key])
    }

    public func checkServerCert(host: String, port: Int) throws -> String {
        try runVpncmd(arguments: ["\(host):\(port)", "/CMD", "Check"])
    }
}

