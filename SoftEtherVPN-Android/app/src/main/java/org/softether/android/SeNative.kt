package org.softether.android

import android.content.Context
import java.io.File

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
    var proxyHost: String = "",
    var proxyPort: Int = 0,
    var triples: Array<String>? = null,
) {
    // SoftEther new-format ("declare root") account path prefix
    private val acc get() = "AccountDatabase/Account0"
    private val co get() = "$acc/ClientOption/"
    private val ca get() = "$acc/ClientAuth/"
    private val ao get() = "$acc/AndroidOptions/"

    fun toCfg(): String {
        val t = triples

        if (t == null) {
            return buildString {
                appendLine("# SoftEther VPN Android connection profile")
                appendLine("host=$host")
                appendLine("port=$port")
                appendLine("hub=$hub")
                appendLine("user=$user")
                if (pass != null) appendLine("pass=$pass")
                appendLine("encrypt=${if (encrypt) "true" else "false"}")
                appendLine("compress=${if (compress) "true" else "false"}")
                appendLine("ipv4=${if (dhcp) "dhcp" else "static"}")
                appendLine("ipv4_on=${if (useIpv4) "true" else "false"}")
                appendLine("ipv6=${if (useIpv6) "true" else "false"}")
                appendLine("ipv6_mode=${if (ra6) "ra" else "static"}")
                appendLine("routes4=${if (routesAuto4) "auto" else "manual"}")
                appendLine("routes6=${if (routesAuto6) "auto" else "manual"}")
                if (manualRoutes4.isNotEmpty()) appendLine("routes4_manual=$manualRoutes4")
                if (ignoreRoutes4.isNotEmpty()) appendLine("routes4_ignore=$ignoreRoutes4")
                if (manualRoutes6.isNotEmpty()) appendLine("routes6_manual=$manualRoutes6")
                if (ignoreRoutes6.isNotEmpty()) appendLine("routes6_ignore=$ignoreRoutes6")
                if (!dhcp && staticIp.isNotEmpty()) {
                    appendLine("static_ip=$staticIp")
                    appendLine("static_mask=$staticMask")
                    if (staticGw.isNotEmpty()) appendLine("static_gw=$staticGw")
                }
                if (dns1.isNotEmpty()) appendLine("dns1=$dns1")
                if (dns2.isNotEmpty()) appendLine("dns2=$dns2")
                if (staticIpv6.isNotEmpty()) {
                    appendLine("static_ip6=$staticIpv6")
                    appendLine("static_mask6=$staticMask6")
                    if (staticGw6.isNotEmpty()) appendLine("static_gw6=$staticGw6")
                }
                if (dns6.isNotEmpty()) appendLine("dns6=$dns6")
                if (proxyHost.isNotEmpty()) {
                    appendLine("proxy_host=$proxyHost")
                    appendLine("proxy_port=$proxyPort")
                }
            }
        }

        val nt = t.toMutableList()

        fun get(path: String, type: String? = null): String? {
            for (i in nt.indices step 3) {
                if (nt[i] == path && (type == null || nt[i + 1] == type)) return nt[i + 2]
            }
            return null
        }

        fun set(path: String, type: String, value: String) {
            for (i in nt.indices step 3) {
                if (nt[i] == path) {
                    nt[i + 2] = value
                    return
                }
            }
            nt.addAll(listOf(path, type, value))
        }

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

        val at = get(ca + "AuthType", "uint")?.toIntOrNull() ?: 0
        val p = pass
        when {
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

        fun remove(path: String) {
            var i = 0
            while (i < nt.size) {
                if (nt[i] == path) {
                    repeat(3) { nt.removeAt(i) }
                } else {
                    i += 3
                }
            }
        }

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

        return try {
            SeNative.nativeCfgCompose(nt.toTypedArray())
        } catch (e: Exception) {
            SeNative.lastError = "CFG save failed: ${e.message}"
            ""
        }
    }

    companion object {
        fun fromCfg(text: String): SeConfig {
            if (text.contains("declare")) {
                try {
                    val t = SeNative.nativeCfgParse(text)
                    if (t != null && t.size % 3 == 0 && t.isNotEmpty()) {
                        return fromTriples(t)
                    }
                } catch (e: Exception) {
                    SeNative.lastError = "CFG parse failed: ${e.message}"
                }
                return SeConfig()
            }

            val c = SeConfig()
            fun field(line: String, key: String): Boolean {
                val eq = line.indexOf('=')
                if (eq < 0 || line.substring(0, eq).trim() != key) return false
                val v = line.substring(eq + 1).trim()
                when (key) {
                    "host" -> c.host = v
                    "port" -> c.port = v.toIntOrNull() ?: c.port
                    "hub" -> c.hub = v
                    "user" -> c.user = v
                    "pass" -> c.pass = v
                    "encrypt" -> c.encrypt = v != "false"
                    "compress" -> c.compress = v == "true"
                    "ipv4" -> c.dhcp = v != "static"
                    "ipv4_on" -> c.useIpv4 = v != "false"
                    "ipv6" -> c.useIpv6 = v == "true"
                    "ipv6_mode" -> c.ra6 = v != "static"
                    "routes" -> {
                        c.routesAuto4 = v != "manual"
                        c.routesAuto6 = v != "manual"
                    }
                    "routes4" -> c.routesAuto4 = v != "manual"
                    "routes6" -> c.routesAuto6 = v != "manual"
                    "routes4_manual" -> c.manualRoutes4 = v
                    "routes4_ignore" -> c.ignoreRoutes4 = v
                    "routes6_manual" -> c.manualRoutes6 = v
                    "routes6_ignore" -> c.ignoreRoutes6 = v
                    "static_ip" -> c.staticIp = v
                    "static_mask" -> c.staticMask = v
                    "static_gw" -> c.staticGw = v
                    "dns1" -> c.dns1 = v
                    "dns2" -> c.dns2 = v
                    "static_ip6" -> c.staticIpv6 = v
                    "static_mask6" -> c.staticMask6 = v
                    "static_gw6" -> c.staticGw6 = v
                    "dns6" -> c.dns6 = v
                    "proxy_host" -> c.proxyHost = v
                    "proxy_port" -> c.proxyPort = v.toIntOrNull() ?: c.proxyPort
                }
                return true
            }
            for (raw in text.split("\r", "\n")) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                field(line, "host"); field(line, "port"); field(line, "hub")
                field(line, "user"); field(line, "pass"); field(line, "encrypt")
                field(line, "compress"); field(line, "ipv4"); field(line, "static_ip")
                field(line, "static_mask"); field(line, "static_gw"); field(line, "dns1")
                field(line, "dns2"); field(line, "proxy_host"); field(line, "proxy_port")
                field(line, "ipv4_on"); field(line, "ipv6"); field(line, "ipv6_mode")
                field(line, "static_ip6"); field(line, "static_mask6")
                field(line, "static_gw6"); field(line, "dns6"); field(line, "routes")
                field(line, "routes4"); field(line, "routes6")
                field(line, "routes4_manual"); field(line, "routes4_ignore")
                field(line, "routes6_manual"); field(line, "routes6_ignore")
            }
            return c
        }

        private fun fromTriples(t: Array<String>): SeConfig {
            val c = SeConfig(triples = t)

            fun get(path: String, type: String? = null): String? {
                for (i in t.indices step 3) {
                    if (t[i] == path && (type == null || t[i + 1] == type)) return t[i + 2]
                }
                return null
            }

            val co = "AccountDatabase/Account0/ClientOption/"
            val ca = "AccountDatabase/Account0/ClientAuth/"
            val ao = "AccountDatabase/Account0/AndroidOptions/"

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

            val pt = get(co + "ProxyType", "uint")?.toIntOrNull() ?: 0
            c.proxyHost = if (pt != 0) get(co + "ProxyName") ?: "" else ""
            c.proxyPort = get(co + "ProxyPort", "uint")?.toIntOrNull() ?: 0

            return c
        }
    }
}

object SeNative {
    const val STATUS_CONNECTING = 0
    const val STATUS_CONFIG_OK = 1
    const val STATUS_CONFIG_ERROR = 2
    const val STATUS_DISCONNECTED = 3

    @Volatile
    var handle: Long = 0L

    @Volatile
    var lastError: String = ""

    @Volatile
    var negotiating: String = ""

    @Volatile
    var negotiatedIp: String = ""

    // elapsedRealtime() at the moment the next connection attempt may start (0 = none)
    @Volatile
    var retryDeadlineMs: Long = 0L

    private var initialized = false

    init {
        System.loadLibrary("softether")
    }

    fun initOnce() = synchronized(this) {
        if (!initialized) {
            nativeInit()
            initialized = true
        }
    }

    // Extract hamcore and initialize Mayaqua/Cedar from the UI process;
    // the VpnEngine worker calls the same thing lazily before connecting.
    fun prepareAndInit(context: Context) {
        val hamcore = File(context.filesDir, "hamcore.se2")
        if (!hamcore.exists() || hamcore.length() == 0L) {
            context.assets.open("hamcore.se2").use { input ->
                hamcore.outputStream().use { out -> input.copyTo(out) }
            }
        }
        nativeSetPaths(hamcore.absolutePath, context.cacheDir.absolutePath)
        initOnce()
    }

    fun disconnectOnce(handle: Long) {
        synchronized(this) {
            if (this.handle == handle && handle != 0L) {
                this.handle = 0L
                nativeDisconnect(handle)
            }
        }
    }

    external fun nativeSetPaths(hamcorePath: String?, tmpDir: String?)
    external fun nativeInit()
    external fun nativeRelease()
    external fun nativeConnect(cfg: String): Long
    external fun nativeGetStatus(handle: Long): Int
    external fun nativeGetStatusText(handle: Long): String
    external fun nativeGetIPv4Info(handle: Long): Array<String>?
    external fun nativeGetIPv6Config(handle: Long): Array<String>?
    external fun nativeGetConnInfo(handle: Long): Array<String>?
    external fun nativeSetTunFd(handle: Long, fd: Int)
    external fun nativeDisconnect(handle: Long)

    // CFG text bridge (require nativeInit to have run via prepareAndInit)
    external fun nativeCfgDefault(accountName: String): String
    external fun nativeCfgParse(cfg: String): Array<String>?
    external fun nativeCfgCompose(triples: Array<String>): String
    external fun nativeHashPassword(user: String, pass: String): String
    external fun nativeEncryptPassword(pass: String): String
    external fun nativeDecryptPassword(b64: String): String
}
