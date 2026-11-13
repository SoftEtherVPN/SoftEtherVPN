package org.softether.android

import android.content.Context
import android.util.Log
import java.io.File
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

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

    // Id of the profile the engine is connected (or connecting) as ("" = none);
    // set/cleared by VpnEngine. Widget and QS tile derive their state from this.
    @Volatile
    var activeProfileId: String = ""

    private var initialized = false

    init {
        System.loadLibrary("softether")
    }

    // SoftEther core version ("5.02.<build>"); nativeGetCoreVersion needs the
    // Mayaqua runtime up, so it is fetched in initOnce ("" until then)
    @Volatile
    var coreVersion: String = ""

    fun initOnce() = synchronized(this) {
        if (!initialized) {
            nativeInit()
            seedCaAnchors()
            coreVersion = runCatching { nativeGetCoreVersion() }.getOrDefault("")
            initialized = true
        }
    }

    // Root of trust for server-certificate verification: the Android system
    // store including user-imported CA certificates, handed to Cedar as DER
    // anchors (the OpenSSL default paths are empty under Bionic).
    private fun seedCaAnchors() {
        runCatching {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            val anchors = tmf.trustManagers
                .filterIsInstance<X509TrustManager>()
                .firstOrNull()?.acceptedIssuers ?: emptyArray()
            var n = 0
            for (a in anchors) n += nativeAddCaCert(a.encoded)
            Log.i("SETH", "CA anchors seeded: $n of ${anchors.size}")
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
    external fun nativeGetCoreVersion(): String
    external fun nativeAddCaCert(der: ByteArray): Int
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
