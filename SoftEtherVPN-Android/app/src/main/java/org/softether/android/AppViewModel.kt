package org.softether.android

import android.app.Application
import android.content.Context
import android.net.Uri
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// All durable screen state and flows: profiles, the CFG form, per-app routing,
// session polling and profile CRUD. App() keeps only transient dialog/navigation
// visibility. Dialog data (nameDlg/nameText/pendingSrc) lives here so a config
// change does not lose a half-open create/rename.
class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val ctx: Context get() = getApplication()

    val prefs = app.getSharedPreferences("profile", Context.MODE_PRIVATE)

    var entries by mutableStateOf(listOf<ProfileEntry>())
    var curId by mutableStateOf("")

    var cfg by mutableStateOf(SeConfig())
    var portStr by mutableStateOf("")
    var raw by mutableStateOf("")
    var rawMode by mutableStateOf(false)

    // SoftEther core version, readable only after prepareAndInit
    var coreVer by mutableStateOf(SeNative.coreVersion)

    // Per-app routing is a profile property (AndroidOptions.AppMode/AppList);
    // these states mirror the current profile's SeConfig.
    var appMode by mutableStateOf("off")
    var appSet by mutableStateOf(setOf<String>())

    var statusText by mutableStateOf("Idle")
    var connInfo by mutableStateOf("")
    var busy by mutableStateOf(false)
    var sessionAlive by mutableStateOf(false)

    var nameText by mutableStateOf("")

    // cfg text of a not-yet-created profile while its name dialog is open
    // (null = plain rename); Cancel in the dialog discards it uncreated
    var pendingSrc by mutableStateOf<String?>(null)

    // mode, auto name, target id; null = closed
    var nameDlg by mutableStateOf<Triple<String, String, String>?>(null)

    init {
        load()
    }

    private fun load() {
        curId = ProfileStore.currentId(ctx)
        entries = ProfileStore.all(ctx)
        val saved = ProfileStore.loadCurrent(ctx)
        SeNative.prepareAndInit(ctx)
        coreVer = SeNative.coreVersion
        cfg = SeConfig.fromCfg(saved)
        // one-time migration: pre-vc30 builds kept app routing in app-level
        // prefs; adopt it unless the profile carries its own value
        val legacyMode = prefs.getString("appMode", "off") ?: "off"
        if (legacyMode != "off" && cfg.appMode == "off") {
            cfg = cfg.copy(appMode = legacyMode, appList = prefs.getString("appList", "") ?: "")
            ProfileStore.putCfg(ctx, curId, cfg.toCfg())
        }
        prefs.edit().remove("appMode").remove("appList").apply()
        portStr = cfg.port.toString()
        raw = cfg.toCfg()
        syncAppRoute(cfg)

        viewModelScope.launch {
            while (true) {
                poll()
                delay(500)
            }
        }
    }

    private fun poll() {
        val h = SeNative.handle
        val neg = SeNative.negotiating
        val dl = SeNative.retryDeadlineMs
        val rem = if (dl > 0L) ((dl - SystemClock.elapsedRealtime() + 999) / 1000) else -1L
        val act = SeNative.activeProfileId
        val otherActive = act.isNotEmpty() && act != curId
        sessionAlive = h != 0L || neg.isNotEmpty() || rem > 0L
        busy = sessionAlive && !otherActive
        val ip4 = if (h != 0L) acquiredIp4(h) else ""
        val ip6 = if (h != 0L) acquiredIp6(h) else ""
        statusText = when {
            otherActive -> {
                val e = entries.find { it.id == act }
                    ?: ProfileStore.all(ctx).find { it.id == act }
                val label = e?.let { ProfileStore.displayName(it) } ?: act
                "Idle, connected profile \"$label\""
            }
            h != 0L -> statusLine(SeNative.nativeGetStatusText(h), ip4, ip6)
            neg.isNotEmpty() -> neg
            SeNative.lastError.isNotEmpty() ->
                if (rem > 0L) SeNative.lastError + " (next attempt in ${rem}s)"
                else SeNative.lastError
            else -> "Idle"
        }
        connInfo = if (h != 0L && !otherActive) {
            val tls = formatConnInfo(SeNative.nativeGetConnInfo(h))
            // labeled per-family addresses in every state; negotiatedIp only as fallback
            val labeled = listOfNotNull(
                if (ip4.isNotEmpty()) "IPv4 $ip4" else null,
                if (ip6.isNotEmpty()) "IPv6 $ip6" else null,
            ).joinToString(", ")
            val assigned = SeNative.negotiatedIp
            val ipLine = when {
                labeled.isNotEmpty() -> "IP: $labeled"
                assigned.isNotEmpty() -> "IP: $assigned"
                else -> ""
            }
            (if (ipLine.isEmpty()) "" else "$ipLine\n") + tls
        } else ""
    }

    fun effectiveCfg(): String = if (rawMode) raw else cfg.toCfg()

    fun savePrefs() {
        if (curId.isNotEmpty()) ProfileStore.putCfg(ctx, curId, effectiveCfg())
    }

    fun refreshEntries() {
        entries = ProfileStore.all(ctx)
    }

    fun refreshAutoName() {
        val e = entries.find { it.id == curId } ?: return
        if (e.custom) return
        val auto = ProfileStore.defaultName(cfg.user, cfg.host)
        if (auto != e.name) {
            val updated = entries.map { if (it.id == curId) it.copy(name = auto) else it }
            ProfileStore.save(ctx, updated, curId)
            entries = updated
        }
    }

    private fun derivedAutoName(id: String): String {
        val c = runCatching { SeConfig.fromCfg(ProfileStore.cfgText(ctx, id)) }.getOrNull()
        return ProfileStore.defaultName(c?.user, c?.host)
    }

    fun syncAppRoute(c: SeConfig) {
        appMode = c.appMode
        appSet = c.appList.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet()
    }

    fun persistApps(mode: String, set: Set<String>) {
        val list = set.joinToString(",")
        appMode = mode
        appSet = set
        if (rawMode) {
            val parsed = runCatching { SeConfig.fromCfg(raw) }.getOrNull()
            if (parsed != null) {
                parsed.appMode = mode
                parsed.appList = list
                raw = parsed.toCfg()
            }
        } else {
            cfg = cfg.copy(appMode = mode, appList = list)
        }
    }

    fun onRawMode(on: Boolean) {
        rawMode = on
        if (on) {
            raw = cfg.toCfg()
        } else {
            cfg = SeConfig.fromCfg(raw)
            portStr = cfg.port.toString()
            syncAppRoute(cfg)
        }
    }

    fun onAppMode(m: String) {
        appMode = m
        persistApps(m, appSet)
    }

    fun onAppSet(set: Set<String>) {
        appSet = set
        persistApps(appMode, set)
    }

    private fun loadProfileIntoUi(id: String) {
        val loaded =
            runCatching { SeConfig.fromCfg(ProfileStore.cfgText(ctx, id)) }.getOrDefault(SeConfig())
        cfg = loaded
        portStr = loaded.port.toString()
        raw = loaded.toCfg()
        rawMode = false
        syncAppRoute(loaded)
    }

    fun applyProfileName(newName: String, id: String) {
        val clean = newName.replace('\t', ' ').replace('\n', ' ').trim()
        val updated = ProfileStore.all(ctx).map {
            if (it.id == id)
                it.copy(name = clean.ifEmpty { derivedAutoName(id) }, custom = clean.isNotEmpty())
            else
                it
        }
        ProfileStore.save(ctx, updated, curId)
        entries = updated
    }

    fun openNameDlg(mode: String, id: String) {
        val e = ProfileStore.all(ctx).find { it.id == id }
        nameText = if (e?.custom == true) e.name else ""
        pendingSrc = null
        nameDlg = Triple(mode, derivedAutoName(id), id)
    }

    // defers profile creation until the name dialog is confirmed;
    // "new" passes an empty cfg text (fresh default config),
    // "duplicate" passes the current profile's stored cfg
    fun beginCreate(mode: String, srcText: String) {
        nameText = ""
        pendingSrc = srcText
        val c = runCatching { SeConfig.fromCfg(srcText) }.getOrNull()
        nameDlg = Triple(mode, ProfileStore.defaultName(c?.user, c?.host), "")
    }

    fun confirmCreate(newName: String) {
        val src = pendingSrc ?: return
        val id = ProfileStore.newId(ctx)
        ProfileStore.putCfg(ctx, id, src)
        val c = runCatching { SeConfig.fromCfg(src) }.getOrNull()
        val clean = newName.replace('\t', ' ').replace('\n', ' ').trim()
        val updated = ProfileStore.all(ctx) +
            ProfileEntry(id, clean.ifEmpty { ProfileStore.defaultName(c?.user, c?.host) }, clean.isNotEmpty())
        ProfileStore.save(ctx, updated, id)
        entries = updated
        curId = id
        loadProfileIntoUi(id)
        pendingSrc = null
    }

    fun switchProfile(id: String) {
        if (id == curId) return
        curId = id
        ProfileStore.save(ctx, entries, id)
        loadProfileIntoUi(id)
    }

    fun deleteCurrent() {
        if (curId.isEmpty()) return
        ProfileStore.removeCfg(ctx, curId)
        val rest = ProfileStore.all(ctx).filter { it.id != curId }
        if (rest.isEmpty()) {
            val e = ProfileEntry("p1", "Default", false)
            ProfileStore.save(ctx, listOf(e), "p1")
            entries = listOf(e)
            curId = "p1"
        } else {
            val act = SeNative.activeProfileId
            val (ren, newCur) = ProfileStore.reindex(ctx, rest, rest.first().id)
            // the connected *other* profile may be renumbered by the survivor
            // shift; keep the session tracking it under its new id
            if (act.isNotEmpty() && act != curId) {
                val k = rest.indexOfFirst { it.id == act }
                if (k >= 0) SeNative.activeProfileId = ren[k].id
            }
            entries = ren
            curId = newCur
        }
        loadProfileIntoUi(curId)
    }

    // swap the current profile with its neighbour; indexes renumber 1..N
    fun moveCurrent(delta: Int) {
        val sorted = ProfileStore.all(ctx)
        val i = sorted.indexOfFirst { it.id == curId }
        val j = i + delta
        if (i < 0 || j < 0 || j >= sorted.size) return
        val swapped = sorted.toMutableList()
        val tmp = swapped[i]
        swapped[i] = swapped[j]
        swapped[j] = tmp
        val act = SeNative.activeProfileId
        val (ren, newCur) = ProfileStore.reindex(ctx, swapped, curId)
        // a connected profile that participated in the swap keeps its session
        // under the new id
        if (act.isNotEmpty()) {
            val k = swapped.indexOfFirst { it.id == act }
            if (k >= 0) SeNative.activeProfileId = ren[k].id
        }
        entries = ren
        curId = newCur
    }

    // SAF OpenDocument result: read, validate, upgrade vc29-era routing markers,
    // and defer creation to the same name dialog used by New/Duplicate
    fun onImportResult(uri: Uri?) {
        if (uri == null) return
        val text = try {
            ctx.contentResolver.openInputStream(uri)?.use {
                it.readBytes().toString(Charsets.UTF_8)
            }?.removePrefix("\uFEFF")
        } catch (e: Exception) {
            null
        }
        val ok = text != null && try {
            !text.contains("declare") || SeNative.nativeCfgParse(text) != null
        } catch (e: Exception) {
            false
        }
        if (ok && text != null) {
            nameText = ""
            pendingSrc = text
            val c = runCatching { SeConfig.fromCfg(text) }.getOrNull()
            // vc29 exports carried routing in "#AndroidApp…" comment
            // markers; upgrade such files into native AndroidOptions keys
            if (c != null && c.appMode == "off") {
                val am = Regex("^#AndroidAppMode=(allow|block)$", RegexOption.MULTILINE)
                    .find(text)?.groupValues?.get(1)
                if (am != null) {
                    val al = Regex("^#AndroidAppList=(.*)$", RegexOption.MULTILINE)
                        .find(text)?.groupValues?.get(1)?.trim().orEmpty()
                    c.appMode = am
                    c.appList = al
                    pendingSrc = c.toCfg()
                }
            }
            nameDlg = Triple("import", ProfileStore.defaultName(c?.user, c?.host), "")
        } else {
            SeNative.lastError = "Import failed: not a valid VPN account file"
        }
    }
}
