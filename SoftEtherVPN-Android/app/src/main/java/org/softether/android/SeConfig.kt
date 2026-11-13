package org.softether.android

// Triple list plumbing: a parsed CFG is a flat list of (path, type, value)
// thrice entries; find the first entry whose path matches, with an optional
// type-string match.
private fun tripleFind(t: List<String>, path: String, type: String?): Int {
    var i = 0
    while (i + 2 < t.size) {
        if (t[i] == path && (type == null || t[i + 1] == type)) return i
        i += 3
    }
    return -1
}

private fun tripleGet(t: List<String>, path: String, type: String?): String? {
    val i = tripleFind(t, path, type)
    return if (i >= 0) t[i + 2] else null
}

private fun tripleSet(t: MutableList<String>, path: String, type: String, value: String) {
    val i = tripleFind(t, path, null)
    if (i >= 0) {
        t[i + 2] = value
        return
    }
    t.addAll(listOf(path, type, value))
}

// removes every entry with this path (duplicate paths possible in desktop CFG)
private fun tripleRemove(t: MutableList<String>, path: String) {
    var i = 0
    while (i < t.size) {
        if (t[i] == path) {
            repeat(3) { t.removeAt(i) }
        } else {
            i += 3
        }
    }
}

data class SeConfig(
    var host: String = "",
    var port: Int = 5555,
    var hub: String = "SERVERVPN",
    var user: String = "",
    var pass: String? = null,
    var encrypt: Boolean = true,
    var compress: Boolean = false,
    var dhcp: Boolean = true,
    var useIpv4: Boolean = true,
    var useIpv6: Boolean = false,
    var ra6: Boolean = true,
    var staticIp: String = "",
    var staticMask: String = "255.255.255.0",
    var staticGw: String = "",
    var dns1: String = "",
    var dns2: String = "",
    var staticIpv6: String = "",
    var staticMask6: String = "64",
    var staticGw6: String = "",
    var dns6: String = "",
    var routesAuto4: Boolean = true,
    var manualRoutes4: String = "",
    var ignoreRoutes4: String = "",
    var routesAuto6: Boolean = true,
    var manualRoutes6: String = "",
    var ignoreRoutes6: String = "",
    var checkServerCert: Boolean = false,
    var proxyHost: String = "",
    var proxyPort: Int = 0,
    var triples: Array<String>? = null,
    var appMode: String = "off",
    var appList: String = "",
) {
    // SoftEther new-format ("declare root") account path prefix
    private val acc get() = "AccountDatabase/Account0"
    private val co get() = "$acc/ClientOption/"
    private val ca get() = "$acc/ClientAuth/"
    private val ao get() = "$acc/AndroidOptions/"

    // The CFG text ("declare root") is the only configuration format: compose it
    // from the parsed profile triples, or from scratch when the config was never
    // parsed from CFG.
    fun toCfg(): String {
        val nt = (triples ?: emptyArray<String>()).toMutableList()

        fun get(path: String, type: String? = null): String? = tripleGet(nt, path, type)

        fun set(path: String, type: String, value: String) = tripleSet(nt, path, type, value)

        // keep any "/hint" suffix appended to the hostname by the desktop client
        val oldHost = get(co + "Hostname")
        val hostVal = if (oldHost != null && oldHost.contains('/')) {
            host + "/" + oldHost.substringAfterLast('/')
        } else {
            host
        }

        set(co + "Hostname", "string", hostVal)
        set(co + "Port", "uint", port.toString())
        set(co + "HubName", "string", hub)
        set(ca + "Username", "string", user)
        set(co + "UseEncrypt", "bool", encrypt.toString())
        set(co + "UseCompress", "bool", compress.toString())
        // desktop default when a profile omits it (the UI has no toggle yet)
        if (get(co + "HalfConnection") == null) set(co + "HalfConnection", "bool", "true")

        val at = get(ca + "AuthType", "uint")?.toIntOrNull() ?: 0
        val p = pass
        when {
            // certificate authentication: the profile carries ClientCert/ClientKey,
            // a password is not part of it — never rewrite the auth form
            at == 3 -> {}
            p == null -> {}
            p.isEmpty() -> {
                set(ca + "AuthType", "uint", "0")
                set(ca + "HashedPassword", "byte", "0")
                set(ca + "EncryptedPassword", "byte", "0")
            }
            at == 2 -> set(ca + "EncryptedPassword", "byte", SeNative.nativeEncryptPassword(p))
            else -> {
                set(ca + "AuthType", "uint", "1")
                set(ca + "HashedPassword", "byte", SeNative.nativeHashPassword(user, p))
            }
        }

        set(co + "ProxyType", "uint", if (proxyHost.isEmpty()) "0" else "3")
        set(co + "ProxyName", "string", proxyHost)
        set(co + "ProxyPort", "uint", proxyPort.toString())

        fun remove(path: String) = tripleRemove(nt, path)

        // Android-only options live in their own folder, never inside the
        // native ClientOption
        set(ao + "UseIPv4", "bool", useIpv4.toString())
        set(ao + "UseIPv6", "bool", useIpv6.toString())
        set(ao + "IPv4Mode", "string", if (dhcp) "dhcp" else "static")
        set(ao + "IPv6Mode", "string", if (ra6) "ra" else "static")
        set(ao + "StaticIp", "string", staticIp)
        set(ao + "StaticMask", "string", staticMask)
        set(ao + "StaticGw", "string", staticGw)
        set(ao + "Dns1", "string", dns1)
        set(ao + "Dns2", "string", dns2)
        set(ao + "StaticIPv6", "string", staticIpv6)
        set(ao + "StaticMask6", "string", staticMask6)
        set(ao + "StaticGw6", "string", staticGw6)
        set(ao + "StaticDns6", "string", dns6)
        set(ao + "RoutesMode4", "string", if (routesAuto4) "auto" else "manual")
        set(ao + "RoutesMode6", "string", if (routesAuto6) "auto" else "manual")
        set(ao + "ManualRoutes4", "string", manualRoutes4)
        set(ao + "IgnoreRoutes4", "string", ignoreRoutes4)
        set(ao + "ManualRoutes6", "string", manualRoutes6)
        set(ao + "IgnoreRoutes6", "string", ignoreRoutes6)
        remove(ao + "RoutesMode")
        if (appMode != "off") {
            set(ao + "AppMode", "string", appMode)
            set(ao + "AppList", "string", appList)
        } else {
            remove(ao + "AppMode")
            remove(ao + "AppList")
        }

        // Native account-root key (server certificate verification)
        set("$acc/CheckServerCert", "bool", checkServerCert.toString())

        return try {
            SeNative.nativeCfgCompose(nt.toTypedArray())
        } catch (e: Exception) {
            SeNative.lastError = "CFG save failed: ${e.message}"
            ""
        }
    }

    companion object {
        // Any profile text is SoftEther account CFG; anything that does not
        // parse as such is invalid input (defaults, with the error surfaced).
        fun fromCfg(text: String): SeConfig {
            if (text.isBlank()) {
                return SeConfig()
            }

            val t = try {
                SeNative.nativeCfgParse(text)
            } catch (e: Exception) {
                SeNative.lastError = "CFG parse failed: ${e.message}"
                null
            }

            return if (t != null && t.size % 3 == 0 && t.isNotEmpty()) {
                fromTriples(t)
            } else {
                SeNative.lastError = "Not a SoftEther account CFG."
                SeConfig()
            }
        }

        private fun fromTriples(t: Array<String>): SeConfig {
            val c = SeConfig(triples = t)

            fun get(path: String, type: String? = null): String? =
                tripleGet(t.asList(), path, type)

            val co = "AccountDatabase/Account0/ClientOption/"
            val ca = "AccountDatabase/Account0/ClientAuth/"
            val ao = "AccountDatabase/Account0/AndroidOptions/"
            val acc = "AccountDatabase/Account0/"

            c.host = get(co + "Hostname")?.substringBefore('/') ?: ""
            c.port = get(co + "Port", "uint")?.toIntOrNull() ?: 5555
            c.hub = get(co + "HubName")?.takeIf { it.isNotEmpty() } ?: "SERVERVPN"
            c.user = get(ca + "Username") ?: ""
            c.encrypt = get(co + "UseEncrypt", "bool")?.toBooleanStrictOrNull() ?: true
            c.compress = get(co + "UseCompress", "bool")?.toBooleanStrictOrNull() ?: false

            val at = get(ca + "AuthType", "uint")?.toIntOrNull() ?: 0
            c.pass = when (at) {
                1 -> null // hashed password stays as stored
                2 -> get(ca + "EncryptedPassword", "byte")?.let {
                    try {
                        SeNative.nativeDecryptPassword(it)
                    } catch (e: Exception) {
                        ""
                    }
                }
                else -> ""
            }

            c.dhcp = get(ao + "IPv4Mode") != "static"
            c.useIpv4 = get(ao + "UseIPv4", "bool")?.toBooleanStrictOrNull() ?: true
            c.useIpv6 = get(ao + "UseIPv6", "bool")?.toBooleanStrictOrNull() ?: false
            c.ra6 = (get(ao + "IPv6Mode") ?: "ra") != "static"
            c.staticIp = get(ao + "StaticIp") ?: ""
            c.staticMask = get(ao + "StaticMask")?.takeIf { it.isNotEmpty() } ?: "255.255.255.0"
            c.staticGw = get(ao + "StaticGw") ?: ""
            c.dns1 = get(ao + "Dns1") ?: ""
            c.dns2 = get(ao + "Dns2") ?: ""
            c.staticIpv6 = get(ao + "StaticIPv6") ?: ""
            c.staticMask6 = get(ao + "StaticMask6")?.takeIf { it.isNotEmpty() } ?: "64"
            c.staticGw6 = get(ao + "StaticGw6") ?: ""
            c.dns6 = get(ao + "StaticDns6") ?: ""
            val rmLegacy = get(ao + "RoutesMode")
            c.routesAuto4 = (get(ao + "RoutesMode4") ?: rmLegacy ?: "auto") != "manual"
            c.routesAuto6 = (get(ao + "RoutesMode6") ?: rmLegacy ?: "auto") != "manual"
            c.manualRoutes4 = get(ao + "ManualRoutes4") ?: ""
            c.ignoreRoutes4 = get(ao + "IgnoreRoutes4") ?: ""
            c.manualRoutes6 = get(ao + "ManualRoutes6") ?: ""
            c.ignoreRoutes6 = get(ao + "IgnoreRoutes6") ?: ""
            c.appMode = get(ao + "AppMode")?.takeIf { it == "allow" || it == "block" } ?: "off"
            c.appList = get(ao + "AppList") ?: ""
            c.checkServerCert = get(acc + "CheckServerCert", "bool")?.toBooleanStrictOrNull() ?: false

            val pt = get(co + "ProxyType", "uint")?.toIntOrNull() ?: 0
            c.proxyHost = if (pt != 0) get(co + "ProxyName") ?: "" else ""
            c.proxyPort = get(co + "ProxyPort", "uint")?.toIntOrNull() ?: 0

            return c
        }
    }
}
