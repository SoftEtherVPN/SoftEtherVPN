package org.softether.android

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.InetAddresses
import android.net.VpnService
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import java.io.File

class VpnEngine : VpnService() {

    companion object {
        const val ACTION_CONNECT = "org.softether.android.action.CONNECT"
        const val ACTION_STOP = "org.softether.android.action.STOP"
        const val ACTION_STATE_CHANGED = "org.softether.android.action.STATE_CHANGED"
        const val EXTRA_CFG = "cfg"
        const val EXTRA_PROFILE = "profile"
        private const val RECONNECT_BASE_MS = 5000L
        private const val RECONNECT_MAX_MS = 30000L
        private const val CONNECT_TIMEOUT_MS = 90000L
        private const val ACTION_REVOKE = "android.net.VpnService.ACTION_REVOKE"
    }

    private var lastNotified = ""

    @Volatile
    private var stopRequested = false

    @Volatile
    private var generation = 0

    @Volatile
    private var pendingCfg = ""

    @Volatile
    private var worker: Thread? = null

    // Retry policy parameters taken from the profile CFG (native semantics):
    // NumRetry extra attempts after the first failure, RetryInterval ms between.
    private var cfgRetries = 3
    private var cfgRetryIntervalMs = 10000L
    private var lastParsedCfg = ""

    // Protocol enable flags (profile AndroidOptions.UseIPv4/UseIPv6). The VPN
    // interface is only established when every enabled protocol is configured.
    private var cfgUseIpv4 = true
    private var cfgUseIpv6 = false
    private var cfgRoutesAuto4 = true
    private var cfgRoutesAuto6 = true
    private var cfgManualRoutes4 = ""
    private var cfgIgnoreRoutes4 = ""
    private var cfgManualRoutes6 = ""
    private var cfgIgnoreRoutes6 = ""
    // Per-app routing (profile AndroidOptions.AppMode/AppList)
    private var cfgAppMode = "off"
    private var cfgAppPkgs = setOf<String>()

    private var wakeLock: android.os.PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("SETH", "service: ${intent?.action ?: "restart"}")
        when (intent?.action) {
            ACTION_CONNECT -> {
                startForegroundNotification()
                pendingCfg = intent.getStringExtra(EXTRA_CFG) ?: loadSavedCfg()
                SeNative.activeProfileId = intent.getStringExtra(EXTRA_PROFILE)
                    ?.takeIf { it.isNotEmpty() } ?: ProfileStore.currentId(this)
                val w = worker
                if (w != null && w.isAlive) {
                    generation++
                    SeNative.lastError = ""
                    SeNative.disconnectOnce(SeNative.handle)
                } else {
                    stopRequested = false
                    SeNative.lastError = ""
                    worker = Thread { workerMain() }.also { it.start() }
                }
                notifyStatus("Connecting…")
            }
            ACTION_STOP -> {
                stopRequested = true
                generation++
                SeNative.activeProfileId = ""
                SeNative.disconnectOnce(SeNative.handle)
                sendStateUpdate()
                val w = worker
                if (SeNative.handle == 0L && (w == null || !w.isAlive)) {
                    stopSelf()
                }
            }
            ACTION_REVOKE -> {
                stopRequested = true
                generation++
                SeNative.activeProfileId = ""
                SeNative.lastError = "VPN permission was revoked."
                SeNative.disconnectOnce(SeNative.handle)
                sendStateUpdate()
                stopSelf()
            }
            null -> {
                val w = worker
                if (SeNative.handle == 0L && (w == null || !w.isAlive)) {
                    startForegroundNotification()
                    pendingCfg = loadSavedCfg()
                    SeNative.activeProfileId = ProfileStore.currentId(this)
                    if (pendingCfg.isNotEmpty()) {
                        stopRequested = false
                        worker = Thread { workerMain() }.also { it.start() }
                    }
                }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Log.i("SETH", "service: onRevoke")
        stopRequested = true
        generation++
        SeNative.activeProfileId = ""
        SeNative.lastError = "VPN permission was revoked."
        SeNative.disconnectOnce(SeNative.handle)
        sendStateUpdate()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopRequested = true
        SeNative.activeProfileId = ""
        SeNative.disconnectOnce(SeNative.handle)
        sendStateUpdate()
        super.onDestroy()
    }

    private fun loadSavedCfg(): String = ProfileStore.loadCurrent(this)

    private fun hasNetwork(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val n = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(n) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun startForegroundNotification() {
        VpnNotifier.ensureChannel(this)
        lastNotified = ""
        startForeground(VpnNotifier.NOTIFICATION_ID, VpnNotifier.build(this, "Connecting…"))
    }

    // Single funnel for the notification text: phase changes come through here,
    // no addresses; each accepted change also pushes the widget/QS-tile refresh.
    private fun notifyStatus(text: String) {
        if (text == lastNotified) return
        lastNotified = text
        VpnNotifier.notifyText(this, text)
        sendStateUpdate()
    }

    private fun sendStateUpdate() = VpnNotifier.broadcastState(this)

    private fun sleepWithWake(ms: Long, myGen: Int): Boolean {
        var remaining = ms
        while (remaining > 0) {
            if (stopRequested || generation != myGen) return false
            try {
                Thread.sleep(minOf(200L, remaining))
            } catch (e: InterruptedException) {
                return false
            }
            remaining -= 200
        }
        return true
    }

    private fun parseRetryParams(cfg: String) {
        if (cfg == lastParsedCfg) return
        lastParsedCfg = cfg
        var tries = 3
        var interval = 10000L
        var v4a: Boolean? = null
        var v6a: Boolean? = null
        var routes: String? = null
        var r4: String? = null
        var r6: String? = null
        var man4: String? = null
        var ign4: String? = null
        var man6: String? = null
        var ign6: String? = null
        var appM: String? = null
        var appL: String? = null
        try {
            val t = SeNative.nativeCfgParse(cfg)
            if (t != null) {
                for (i in t.indices step 3) {
                    when (t[i]) {
                        "AccountDatabase/Account0/ClientOption/NumRetry" ->
                            tries = t[i + 2].toIntOrNull() ?: tries
                        "AccountDatabase/Account0/ClientOption/RetryInterval" ->
                            interval = t[i + 2].toLongOrNull() ?: interval
                        "AccountDatabase/Account0/AndroidOptions/UseIPv4" ->
                            v4a = t[i + 2].toBooleanStrictOrNull()
                        "AccountDatabase/Account0/AndroidOptions/UseIPv6" ->
                            v6a = t[i + 2].toBooleanStrictOrNull()
                        "AccountDatabase/Account0/AndroidOptions/RoutesMode" ->
                            routes = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/RoutesMode4" ->
                            r4 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/RoutesMode6" ->
                            r6 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/ManualRoutes4" ->
                            man4 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/IgnoreRoutes4" ->
                            ign4 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/ManualRoutes6" ->
                            man6 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/IgnoreRoutes6" ->
                            ign6 = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/AppMode" ->
                            appM = t[i + 2]
                        "AccountDatabase/Account0/AndroidOptions/AppList" ->
                            appL = t[i + 2]
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("SETH", "retry cfg parse: ${e.javaClass.simpleName}")
        }
        fun legacy(key: String): String? =
            Regex("^$key=(.*)$", RegexOption.MULTILINE)
                .find(cfg)?.groupValues?.get(1)?.trim()
        val routesLegacy = routes ?: legacy("routes")
        cfgRetries = tries.coerceIn(0, 100)
        cfgRetryIntervalMs = interval.coerceIn(1000L, 600000L)
        cfgUseIpv4 = v4a ?: true
        cfgUseIpv6 = v6a ?: false
        cfgRoutesAuto4 = (r4 ?: legacy("routes4") ?: routesLegacy ?: "auto") != "manual"
        cfgRoutesAuto6 = (r6 ?: legacy("routes6") ?: routesLegacy ?: "auto") != "manual"
        cfgManualRoutes4 = man4 ?: legacy("routes4_manual") ?: ""
        cfgIgnoreRoutes4 = ign4 ?: legacy("routes4_ignore") ?: ""
        cfgManualRoutes6 = man6 ?: legacy("routes6_manual") ?: ""
        cfgIgnoreRoutes6 = ign6 ?: legacy("routes6_ignore") ?: ""
        cfgAppMode = appM?.takeIf { it == "allow" || it == "block" } ?: "off"
        cfgAppPkgs = (appL ?: "").split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
    }

    private fun workerMain() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            val wl = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "SETH:vpn")
            wl.setReferenceCounted(false)
            wl.acquire()
            wakeLock = wl
            workerLoop()
        } catch (e: Exception) {
            SeNative.lastError = "Unexpected error: ${e.javaClass.simpleName}"
            Log.e("SETH", "worker: ${e.javaClass.simpleName}: ${e.message}")
            stopSelf()
        } finally {
            try {
                wakeLock?.release()
            } catch (e: Exception) {
                // ignore
            }
            wakeLock = null
            SeNative.negotiating = ""
            SeNative.negotiatedIp = ""
            SeNative.retryDeadlineMs = 0L
            SeNative.activeProfileId = ""
            sendStateUpdate()
        }
    }

    private fun fail(h: Long, msg: String): Outcome {
        SeNative.negotiating = ""
        if (h != 0L && SeNative.handle == h) {
            SeNative.handle = 0L
        }
        return Outcome.Failed(msg)
    }

    // Central retry funnel: every failure/down event goes through here so the
    // UI shows one consistent message + live countdown to the next attempt.
    private fun retryWait(msg: String, delayMs: Long, myGen: Int): Boolean {
        SeNative.lastError = msg
        SeNative.retryDeadlineMs = SystemClock.elapsedRealtime() + delayMs
        notifyStatus(msg)
        return sleepWithWake(delayMs, myGen)
    }

    private fun workerLoop() {
        var attempt = 0
        var reconnectDelay = RECONNECT_BASE_MS
        var lastGen = -1
        var fatal: String? = null
        while (!stopRequested) {
            val myGen = generation
            val cfg = pendingCfg
            if (cfg.isBlank()) break
            if (myGen != lastGen) {
                attempt = 0
                reconnectDelay = RECONNECT_BASE_MS
                lastGen = myGen
            }
            SeNative.retryDeadlineMs = 0L
            when (val r = establishSession(cfg, myGen)) {
                // A generation bump without an explicit stop is the "connect
                // while a worker is already running" restart (profile switch
                // from the app, tile or widget): re-enter with the new config
                // instead of ending the thread.
                is Outcome.Stopped -> if (stopRequested) break else continue
                is Outcome.Down -> {
                    if (stopRequested || generation != myGen) continue
                    if (!retryWait(r.message, reconnectDelay, myGen)) continue
                    reconnectDelay = minOf(reconnectDelay * 2, RECONNECT_MAX_MS)
                    attempt = 0
                }
                is Outcome.Failed -> {
                    if (!hasNetwork()) {
                        reconnectDelay = minOf(reconnectDelay * 2, RECONNECT_MAX_MS)
                        if (!retryWait(r.message + " (waiting for network)", reconnectDelay, myGen)) continue
                    } else {
                        attempt++
                        if (attempt > cfgRetries) {
                            fatal = r.message
                            break
                        }
                        if (!retryWait(
                                r.message + " (retry $attempt/$cfgRetries)",
                                cfgRetryIntervalMs, myGen
                            )
                        ) continue
                    }
                }
            }
        }
        fatal?.let {
            SeNative.lastError = it
            notifyStatus(it)
            val h = SeNative.handle
            if (h != 0L) SeNative.nativeDisconnect(h)
            SeNative.handle = 0L
        }
        stopSelf()
    }

    private fun establishSession(cfg: String, myGen: Int): Outcome {
        val (hamcorePath, tmpDir) = prepareAssets()
        SeNative.nativeSetPaths(hamcorePath, tmpDir)
        SeNative.initOnce()
        parseRetryParams(cfg)

        SeNative.negotiating = "Creating session..."
        notifyStatus("Creating session...")
        val h = SeNative.nativeConnect(cfg)
        if (h == 0L) {
            return fail(0L, "Connection failed (check address, port and hub).")
        }

        SeNative.handle = h
        SeNative.negotiatedIp = "" // a dialing session has no assigned address yet
        SeNative.negotiating = ""
        var pollDeadline = SystemClock.elapsedRealtime() + CONNECT_TIMEOUT_MS
        var lastPhase = ""
        while (true) {
            if (stopRequested || generation != myGen) {
                SeNative.nativeDisconnect(h)
                return Outcome.Stopped
            }
            when (SeNative.nativeGetStatus(h)) {
                SeNative.STATUS_CONFIG_OK -> {
                    break
                }
                SeNative.STATUS_CONFIG_ERROR, SeNative.STATUS_DISCONNECTED -> {
                    val t = SeNative.nativeGetStatusText(h)
                    SeNative.nativeDisconnect(h)
                    return fail(h, if (t.isEmpty()) "Could not establish the session." else t)
                }
            }
            // Session thread is still retrying: its status text (phase, retry
            // count, error) is progress. Only time out if it stops progressing.
            val phase = SeNative.nativeGetStatusText(h)
            if (phase != lastPhase) {
                lastPhase = phase
                pollDeadline = SystemClock.elapsedRealtime() + CONNECT_TIMEOUT_MS
                notifyStatus(phase)
            }
            if (SystemClock.elapsedRealtime() > pollDeadline) {
                SeNative.nativeDisconnect(h)
                return fail(h, "Connection timed out.")
            }
            Thread.sleep(200)
        }

        if (!cfgUseIpv4 && !cfgUseIpv6) {
            SeNative.nativeDisconnect(h)
            return fail(h, "Both IPv4 and IPv6 are disabled in the profile.")
        }

        val info = SeNative.nativeGetIPv4Info(h)
        if (cfgUseIpv4 && (info == null || info[0].isEmpty())) {
            SeNative.nativeDisconnect(h)
            return fail(h, "No IPv4 configuration received.")
        }

        val v6 = if (cfgUseIpv6) SeNative.nativeGetIPv6Config(h) else null
        if (cfgUseIpv6 && (v6 == null || v6[0].isEmpty())) {
            SeNative.nativeDisconnect(h)
            return fail(h, "No IPv6 configuration received.")
        }

        SeNative.negotiating = "Setting up VPN interface..."
        notifyStatus("Setting up VPN interface...")
        val appMode = cfgAppMode
        val appList = cfgAppPkgs
        val ignore4 = parseNetList(cfgIgnoreRoutes4, false)
        val manual4 = parseNetList(cfgManualRoutes4, false)
        val ignore6 = parseNetList(cfgIgnoreRoutes6, true)
        val manual6 = parseNetList(cfgManualRoutes6, true)
        val routeAdded = HashSet<String>()
        val tun = try {
            Builder().apply {
                setSession("SoftEtherVPN Android")
                setBlocking(true)
                setMtu(1500)
                fun applyApp(pkg: String) {
                    try {
                        if (appMode == "allow") addAllowedApplication(pkg)
                        else addDisallowedApplication(pkg)
                    } catch (e: Exception) {
                        Log.w("SETH", "app filter skip $pkg: ${e.javaClass.simpleName}")
                    }
                }
                when (appMode) {
                    "allow" -> (appList - packageName).forEach { applyApp(it) }
                    "block" -> {
                        appList.forEach { applyApp(it) }
                        addDisallowedApplication(packageName)
                    }
                    else -> addDisallowedApplication(packageName)
                }
                // Route install helper: the public VpnService API has no
                // gateway variant (addRoute is dest/prefix only; verified via
                // javap on the platform jar) — gateways in DHCP option 121
                // are therefore informational, the routes land in the tunnel.
                fun addRouteAddr(dest: String, plen: Int) {
                    try {
                        addRoute(InetAddresses.parseNumericAddress(dest), plen)
                    } catch (e: Exception) {
                        Log.w("SETH", "route skip $dest/$plen: ${e.javaClass.simpleName}")
                    }
                }
                fun addNetRoute(n: Net46) {
                    val host = bigToIp(n.addr, n.bits) ?: return
                    val key = host + "/" + n.plen
                    if (!routeAdded.add(key)) return
                    if (routeAdded.size > 96) {
                        routeAdded.remove(key)
                        Log.w("SETH", "route cap reached, skip $key")
                        return
                    }
                    addRouteAddr(host, n.plen)
                }
                // default route (auto modes) split around bypass prefixes;
                // manual default prefixes get the same treatment
                fun addDefaultSplit(n: Net46, ignores: List<Net46>) {
                    netSubtract(n, ignores, 96).forEach { addNetRoute(it) }
                }
                fun addManualRoutes(manual: List<Net46>, ignores: List<Net46>) {
                    for (n in manual) {
                        if (n.plen == 0) addDefaultSplit(n, ignores)
                        else if (!ignores.any { netContains(it, n) }) addNetRoute(n)
                    }
                }
                if (cfgUseIpv4 && info != null && info[0].isNotEmpty()) {
                    addAddress(info[0], prefixFromMask(info[1]))
                    if (cfgRoutesAuto4) {
                        addDefaultSplit(netV4Default, ignore4)
                        // DHCP classless static routes (option 121),
                        // serialized by the native side as "dest/plen@gw;..."
                        info.getOrNull(5)?.split(';')?.forEach { entry ->
                            val n = parseNetList(entry.substringBefore('@'), false)
                                .firstOrNull()
                            if (n != null && !ignore4.any { ig -> netContains(ig, n) }) {
                                addNetRoute(n)
                            }
                        }
                    }
                    addManualRoutes(manual4, ignore4)
                    if (info[3].isNotEmpty()) addDnsServer(info[3])
                    if (info[4].isNotEmpty()) addDnsServer(info[4])
                }
                if (v6 != null && v6[0].isNotEmpty()) {
                    val plen6 = v6[1].toIntOrNull() ?: 64
                    addAddress(InetAddresses.parseNumericAddress(v6[0]), plen6)
                    if (cfgRoutesAuto6) {
                        addDefaultSplit(netV6Default, ignore6)
                        // The RA/learned prefix (or the static network) as an
                        // explicit route, so it is installed in every routing
                        // table too (auto-derived routes only appear in the
                        // default table)
                        v6.getOrNull(3)?.takeIf { it.isNotEmpty() }?.let { pfx ->
                            val n = parseNetList("$pfx/$plen6", true).firstOrNull()
                            if (n != null && !ignore6.any { ig -> netContains(ig, n) }) {
                                addNetRoute(n)
                            }
                        }
                    }
                    addManualRoutes(manual6, ignore6)
                    if (v6[4].isNotEmpty()) addDnsServer(v6[4])
                }
            }.establish()
        } catch (e: Exception) {
            Log.w("SETH", "establish: ${e.javaClass.simpleName}: ${e.message}")
            null
        }

        if (tun == null) {
            SeNative.nativeDisconnect(h)
            return fail(h, "Could not create the VPN interface.")
        }

        var ipDesc = ""
        if (cfgUseIpv4 && info != null && info[0].isNotEmpty()) {
            ipDesc = info[0] + "/" + prefixFromMask(info[1])
        }
        if (v6 != null && v6[0].isNotEmpty()) {
            ipDesc = (if (ipDesc.isNotEmpty()) ipDesc + "   " else "") +
                v6[0] + "/" + (v6[1].toIntOrNull() ?: 64)
        }
        SeNative.negotiatedIp = ipDesc
        SeNative.nativeSetTunFd(h, tun.fd)
        SeNative.handle = h
        SeNative.negotiating = ""
        notifyStatus("Connected")
        Log.i("SETH", "worker: vpn established")

        while (SeNative.nativeGetStatus(h) != SeNative.STATUS_DISCONNECTED) {
            if (stopRequested || generation != myGen) break
            Thread.sleep(500)
        }

        val downText = SeNative.nativeGetStatusText(h)
        SeNative.handle = 0L
        SeNative.negotiating = ""
        try {
            tun.close()
        } catch (e: Exception) {
            // ignore
        }
        SeNative.nativeDisconnect(h)
        return if (stopRequested || generation != myGen) {
            Outcome.Stopped
        } else {
            Outcome.Down(if (downText.isEmpty()) "link down" else downText)
        }
    }

    private fun prepareAssets(): Pair<String, String> {
        val hamcore = File(filesDir, "hamcore.se2")
        if (!hamcore.exists() || hamcore.length() == 0L) {
            assets.open("hamcore.se2").use { input ->
                hamcore.outputStream().use { out -> input.copyTo(out) }
            }
            Log.i("SETH", "worker: hamcore extracted ${hamcore.length()} bytes")
        }
        return Pair(hamcore.absolutePath, cacheDir.absolutePath)
    }
}

private sealed class Outcome {
    object Stopped : Outcome()
    data class Failed(val message: String) : Outcome()
    data class Down(val message: String) : Outcome()
}
