package org.softether.android

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { App() }
    }
}

private fun formatConnInfo(info: Array<String>?): String {
    if (info == null || info.size < 8) return ""

    val sb = StringBuilder()

    if (info[1].isNotEmpty() || info[2].isNotEmpty()) {
        sb.appendLine("TLS ${info[1]} · ${info[2]} (encrypt ${info[0]})")
    }

    if (info[3].isNotEmpty()) {
        sb.appendLine("Server cert: ${info[3]}")

        if (info[4].isNotEmpty()) {
            sb.appendLine("Issuer: ${info[4]}")
        }

        sb.appendLine("Expires: ${info[5]}")
        sb.appendLine("SHA-1: ${info[6]}")
        sb.append("Verification: ${info[7]}")
    }

    return sb.toString().trimEnd()
}

private fun loadInstalledApps(context: Context): List<Triple<String, String, Boolean>> {
    val pm = context.packageManager
    return try {
        pm.getInstalledApplications(0)
            .map { ai ->
                val label = try {
                    pm.getApplicationLabel(ai).toString()
                } catch (e: Exception) {
                    ai.packageName
                }
                Triple(
                    ai.packageName,
                    label,
                    (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }
            .sortedWith(compareBy({ it.first != context.packageName }, { it.second.lowercase() }))
    } catch (e: Exception) {
        emptyList()
    }
}

private fun acquiredAddrSuffix(h: Long): String {
    val parts = ArrayList<String>()

    runCatching { SeNative.nativeGetIPv4Info(h) }.getOrNull()?.let {
        if (it.isNotEmpty() && it[0].isNotEmpty()) parts.add("IPv4 ${it[0]}")
    }

    runCatching { SeNative.nativeGetIPv6Config(h) }.getOrNull()?.let {
        if (it.isNotEmpty() && it[0].isNotEmpty()) parts.add("IPv6 ${it[0]}")
    }

    return parts.joinToString(", ")
}

private fun startVpn(context: Context, cfgText: String) {
    val i = Intent(context, VpnEngine::class.java)
    i.action = VpnEngine.ACTION_CONNECT
    i.putExtra(VpnEngine.EXTRA_CFG, cfgText)
    ContextCompat.startForegroundService(context, i)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun App() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("profile", Context.MODE_PRIVATE) }

    var cfg by remember { mutableStateOf(SeConfig()) }
    var portStr by remember { mutableStateOf("") }
    var rawMode by remember { mutableStateOf(false) }
    var raw by remember { mutableStateOf("") }
    var showConfig by rememberSaveable { mutableStateOf(false) }

    var entries by remember { mutableStateOf(listOf<ProfileEntry>()) }
    var curId by remember { mutableStateOf("") }
    var profilesMenu by remember { mutableStateOf(false) }
    var nameText by remember { mutableStateOf("") }
    var nameDlg by remember { mutableStateOf<Triple<String, String, String>?>(null) }

    // cfg text of a not-yet-created profile while its name dialog is open
    // (null = plain rename); Cancel in the dialog discards it uncreated
    var pendingSrc by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        curId = ProfileStore.currentId(context)
        entries = ProfileStore.all(context)
        val saved = ProfileStore.loadCurrent(context)
        SeNative.prepareAndInit(context)
        cfg = SeConfig.fromCfg(saved)
        portStr = cfg.port.toString()
        raw = cfg.toCfg()
    }

    var statusText by remember { mutableStateOf("Idle") }
    var connInfo by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    var appMode by remember { mutableStateOf(prefs.getString("appMode", "off") ?: "off") }
    var appSet by remember {
        mutableStateOf((prefs.getString("appList", "") ?: "").split(',').map { it.trim() }
            .filter { it.isNotEmpty() }.toSet())
    }
    var showAppPicker by remember { mutableStateOf(false) }

    fun persistApps(mode: String, set: Set<String>) {
        prefs.edit().putString("appMode", mode).putString("appList", set.joinToString(",")).apply()
    }

    LaunchedEffect(Unit) {
        while (true) {
            val h = SeNative.handle
            val neg = SeNative.negotiating
            val dl = SeNative.retryDeadlineMs
            val rem = if (dl > 0L) ((dl - android.os.SystemClock.elapsedRealtime() + 999) / 1000) else -1L
            busy = h != 0L || neg.isNotEmpty() || rem > 0L
            statusText = when {
                h != 0L -> {
                    val phase = SeNative.nativeGetStatusText(h)
                    val acquired =
                        if (phase.startsWith("Connected")) "" else acquiredAddrSuffix(h)
                    if (acquired.isEmpty()) phase else "$phase  $acquired"
                }
                neg.isNotEmpty() -> neg
                SeNative.lastError.isNotEmpty() ->
                    if (rem > 0L) SeNative.lastError + " (next attempt in ${rem}s)"
                    else SeNative.lastError
                else -> "Idle"
            }
            connInfo = if (h != 0L) {
                val tls = formatConnInfo(SeNative.nativeGetConnInfo(h))
                val ip = SeNative.negotiatedIp
                (if (ip.isNotEmpty()) "IP: $ip\n" else "") + tls
            } else ""
            delay(500)
        }
    }

    fun effectiveCfg(): String = if (rawMode) raw else cfg.toCfg()

    fun savePrefs() {
        if (curId.isNotEmpty()) ProfileStore.putCfg(context, curId, effectiveCfg())
    }

    fun refreshAutoName() {
        val e = entries.find { it.id == curId } ?: return
        if (e.custom) return
        val auto = ProfileStore.defaultName(cfg.user, cfg.host)
        if (auto != e.name) {
            val updated = entries.map { if (it.id == curId) it.copy(name = auto) else it }
            ProfileStore.save(context, updated, curId)
            entries = updated
        }
    }

    fun derivedAutoName(id: String): String {
        val c = runCatching { SeConfig.fromCfg(ProfileStore.cfgText(context, id)) }.getOrNull()
        return ProfileStore.defaultName(c?.user, c?.host)
    }

    fun loadProfileIntoUi(id: String) {
        val loaded =
            runCatching { SeConfig.fromCfg(ProfileStore.cfgText(context, id)) }.getOrDefault(SeConfig())
        cfg = loaded
        portStr = loaded.port.toString()
        raw = loaded.toCfg()
        rawMode = false
    }

    fun applyProfileName(newName: String, id: String) {
        val clean = newName.replace('\t', ' ').replace('\n', ' ').trim()
        val updated = ProfileStore.all(context).map {
            if (it.id == id)
                it.copy(name = clean.ifEmpty { derivedAutoName(id) }, custom = clean.isNotEmpty())
            else
                it
        }
        ProfileStore.save(context, updated, curId)
        entries = updated
    }

    fun openNameDlg(mode: String, id: String) {
        val e = ProfileStore.all(context).find { it.id == id }
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
        val id = ProfileStore.newId(context)
        ProfileStore.putCfg(context, id, src)
        val c = runCatching { SeConfig.fromCfg(src) }.getOrNull()
        val clean = newName.replace('\t', ' ').replace('\n', ' ').trim()
        val updated = ProfileStore.all(context) +
            ProfileEntry(id, clean.ifEmpty { ProfileStore.defaultName(c?.user, c?.host) }, clean.isNotEmpty())
        ProfileStore.save(context, updated, id)
        entries = updated
        curId = id
        loadProfileIntoUi(id)
        pendingSrc = null
    }

    fun switchProfile(id: String) {
        if (id == curId) return
        curId = id
        ProfileStore.save(context, entries, id)
        loadProfileIntoUi(id)
    }

    fun createProfile(mode: String, srcText: String) {
        val id = ProfileStore.newId(context)
        ProfileStore.putCfg(context, id, srcText)
        val updated = ProfileStore.all(context) + ProfileEntry(id, derivedAutoName(id), false)
        ProfileStore.save(context, updated, id)
        entries = updated
        curId = id
        loadProfileIntoUi(id)
        openNameDlg(mode, id)
    }

    fun deleteCurrent() {
        if (curId.isEmpty()) return
        ProfileStore.removeCfg(context, curId)
        val rest = ProfileStore.all(context).filter { it.id != curId }
        if (rest.isEmpty()) {
            val e = ProfileEntry("p1", "Default", false)
            ProfileStore.save(context, listOf(e), "p1")
            entries = listOf(e)
            curId = "p1"
        } else {
            val (ren, newCur) = ProfileStore.reindex(context, rest, rest.first().id)
            entries = ren
            curId = newCur
        }
        loadProfileIntoUi(curId)
    }

    // swap the current profile with its neighbour; indexes renumber 1..N
    fun moveCurrent(delta: Int) {
        val sorted = ProfileStore.all(context)
        val i = sorted.indexOfFirst { it.id == curId }
        val j = i + delta
        if (i < 0 || j < 0 || j >= sorted.size) return
        val swapped = sorted.toMutableList()
        val tmp = swapped[i]
        swapped[i] = swapped[j]
        swapped[j] = tmp
        val (ren, newCur) = ProfileStore.reindex(context, swapped, curId)
        entries = ren
        curId = newCur
    }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val text = try {
                context.contentResolver.openInputStream(uri)?.use {
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
                // defer creation to the same name dialog used by New/Duplicate
                nameText = ""
                pendingSrc = text
                val c = runCatching { SeConfig.fromCfg(text) }.getOrNull()
                nameDlg = Triple("import", ProfileStore.defaultName(c?.user, c?.host), "")
            } else {
                SeNative.lastError = "Import failed: not a valid VPN account file"
            }
        }
    }

    var exportName by remember { mutableStateOf("profile.vpn") }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(effectiveCfg().toByteArray(Charsets.UTF_8))
                }
            } catch (e: Exception) {
                SeNative.lastError = "Export failed: ${e.message}"
            }
        }
    }

    LaunchedEffect(rawMode, cfg, raw) {
        delay(300)
        savePrefs()
        refreshAutoName()
    }

    val vpnPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            startVpn(context, effectiveCfg())
        }
    }

    MaterialTheme {
        BackHandler(enabled = showConfig) { showConfig = false }

        Scaffold(
            topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (!showConfig) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = entries.find { it.id == curId }
                            ?.let { ProfileStore.displayName(it) } ?: "1: Default",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f),
                    )
                    Box {
                        TextButton(onClick = {
                            entries = ProfileStore.all(context)
                            profilesMenu = true
                        }) { Text("Profiles") }
                        DropdownMenu(
                            expanded = profilesMenu,
                            onDismissRequest = { profilesMenu = false },
                        ) {
                            entries.forEach { e ->
                                DropdownMenuItem(
                                    text = {
                                        Text((if (e.id == curId) "◉ " else "○  ") + ProfileStore.displayName(e))
                                    },
                                    onClick = {
                                        profilesMenu = false
                                        savePrefs()
                                        switchProfile(e.id)
                                    },
                                )
                            }
                            Divider()
                            DropdownMenuItem(
                                text = { Text("New profile") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    beginCreate("new", "")
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Duplicate current") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    beginCreate("dup", ProfileStore.cfgText(context, curId))
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Import account file") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    importLauncher.launch(
                                        arrayOf("application/octet-stream", "text/plain"),
                                    )
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Export current") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    exportName = (entries.find { it.id == curId }?.name ?: "profile")
                                        .replace(Regex("""[\\/:*?"<>|]"""), "_") + ".vpn"
                                    exportLauncher.launch(exportName)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Rename current") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    openNameDlg("rename", curId)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Move up") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    moveCurrent(-1)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Move down") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    moveCurrent(1)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Delete current") },
                                enabled = !busy,
                                onClick = {
                                    profilesMenu = false
                                    savePrefs()
                                    deleteCurrent()
                                },
                            )
                        }
                    }
                }

                Text("Status: $statusText")

                if (connInfo.isNotEmpty()) {
                    Text(
                        text = connInfo,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        enabled = !busy,
                        onClick = {
                            savePrefs()
                            val prep = VpnService.prepare(context)
                            if (prep != null) {
                                vpnPermission.launch(prep)
                            } else {
                                startVpn(context, effectiveCfg())
                            }
                        },
                    ) { Text("Connect") }
                    OutlinedButton(
                        enabled = busy,
                        onClick = {
                            val i = Intent(context, VpnEngine::class.java)
                            i.action = VpnEngine.ACTION_STOP
                            context.startService(i)
                        },
                    ) { Text("Disconnect") }
                }

                OutlinedTextField(
                    value = cfg.host,
                    onValueChange = { cfg = cfg.copy(host = it) },
                    label = { Text("Server address") },
                    singleLine = true,
                    readOnly = rawMode,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = portStr,
                    onValueChange = {
                        val digits = it.filter(Char::isDigit)
                        portStr = digits
                        cfg = cfg.copy(port = digits.toIntOrNull() ?: 0)
                    },
                    label = { Text("Port") },
                    singleLine = true,
                    readOnly = rawMode,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = cfg.hub,
                    onValueChange = { cfg = cfg.copy(hub = it) },
                    label = { Text("Virtual Hub") },
                    singleLine = true,
                    readOnly = rawMode,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = cfg.user,
                    onValueChange = { cfg = cfg.copy(user = it) },
                    label = { Text("Username") },
                    singleLine = true,
                    readOnly = rawMode,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = cfg.pass ?: "",
                    onValueChange = { cfg = cfg.copy(pass = it) },
                    label = { Text(if (cfg.pass == null) "Password (stored hashed)" else "Password") },
                    singleLine = true,
                    readOnly = rawMode,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (rawMode) {
                    Text(
                        "Raw configuration mode is active — edit it on the configuration screen.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                OutlinedButton(onClick = { showConfig = true }) { Text("Configuration…") }
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { showConfig = false }) { Text("Back") }
                        Text(
                            "Configuration",
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }

                    Text("Advanced configuration (raw)", modifier = Modifier.padding(top = 8.dp))
                Switch(
                    checked = rawMode,
                    onCheckedChange = {
                        rawMode = it
                        if (it) raw = cfg.toCfg() else {
                            cfg = SeConfig.fromCfg(raw)
                            portStr = cfg.port.toString()
                        }
                    },
                )

                if (rawMode) {
                    OutlinedTextField(
                        value = raw,
                        onValueChange = { raw = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        minLines = 8,
                    )
                    OutlinedButton(
                        onClick = {
                            raw = try {
                                SeNative.nativeCfgDefault("Android VPN Account")
                            } catch (e: Exception) {
                                SeNative.lastError = "CFG unavailable: ${e.message}"
                                raw
                            }
                        },
                    ) { Text("Load default CFG account") }
                } else {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Encrypt", modifier = Modifier.weight(1f))
                        Switch(
                            checked = cfg.encrypt,
                            onCheckedChange = { cfg = cfg.copy(encrypt = it) },
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Compress", modifier = Modifier.weight(1f))
                        Switch(
                            checked = cfg.compress,
                            onCheckedChange = { cfg = cfg.copy(compress = it) },
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("IPv4", modifier = Modifier.weight(1f))
                        Switch(
                            checked = cfg.useIpv4,
                            onCheckedChange = { cfg = cfg.copy(useIpv4 = it) },
                        )
                    }
                    if (cfg.useIpv4) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("IPv4 via DHCP", modifier = Modifier.weight(1f))
                            Switch(
                                checked = cfg.dhcp,
                                onCheckedChange = { cfg = cfg.copy(dhcp = it) },
                            )
                        }
                        if (!cfg.dhcp) {
                            OutlinedTextField(
                                value = cfg.staticIp,
                                onValueChange = { cfg = cfg.copy(staticIp = it) },
                                label = { Text("Static IP") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.staticMask,
                                onValueChange = { cfg = cfg.copy(staticMask = it) },
                                label = { Text("Subnet mask") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.staticGw,
                                onValueChange = { cfg = cfg.copy(staticGw = it) },
                                label = { Text("Gateway") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.dns1,
                                onValueChange = { cfg = cfg.copy(dns1 = it) },
                                label = { Text("DNS 1") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.dns2,
                                onValueChange = { cfg = cfg.copy(dns2 = it) },
                                label = { Text("DNS 2") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("IPv4 routes:", modifier = Modifier.weight(1f))
                            for ((on, lab) in listOf(true to "Auto from DHCP", false to "Manual")) {
                                TextButton(onClick = { cfg = cfg.copy(routesAuto4 = on) }) {
                                    Text(
                                        lab,
                                        color = if (cfg.routesAuto4 == on) MaterialTheme.colorScheme.primary
                                        else MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                        OutlinedTextField(
                            value = cfg.manualRoutes4,
                            onValueChange = { cfg = cfg.copy(manualRoutes4 = it) },
                            label = { Text("Manual routes (addr/prefix, comma sep)") },
                            supportingText = {
                                Text(
                                    if (cfg.routesAuto4) "extra routes through the VPN"
                                    else "the only routes through the VPN; add 0.0.0.0/0 for a default",
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = cfg.ignoreRoutes4,
                            onValueChange = { cfg = cfg.copy(ignoreRoutes4 = it) },
                            label = { Text("Bypass routes (prefixes around the VPN)") },
                            supportingText = {
                                Text("everything else still goes through the default route")
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("IPv6", modifier = Modifier.weight(1f))
                        Switch(
                            checked = cfg.useIpv6,
                            onCheckedChange = { cfg = cfg.copy(useIpv6 = it) },
                        )
                    }
                    if (cfg.useIpv6) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("IPv6 via router RA", modifier = Modifier.weight(1f))
                            Switch(
                                checked = cfg.ra6,
                                onCheckedChange = { cfg = cfg.copy(ra6 = it) },
                            )
                        }
                        if (!cfg.ra6) {
                            OutlinedTextField(
                                value = cfg.staticIpv6,
                                onValueChange = { cfg = cfg.copy(staticIpv6 = it) },
                                label = { Text("Static IPv6 (e.g. 2001:db8::2)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.staticMask6,
                                onValueChange = { cfg = cfg.copy(staticMask6 = it) },
                                label = { Text("Prefix length (64)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            OutlinedTextField(
                                value = cfg.staticGw6,
                                onValueChange = { cfg = cfg.copy(staticGw6 = it) },
                                label = { Text("Gateway (link-local ok)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        OutlinedTextField(
                            value = cfg.dns6,
                            onValueChange = { cfg = cfg.copy(dns6 = it) },
                            label = { Text("DNS (IPv6, optional)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("IPv6 routes:", modifier = Modifier.weight(1f))
                            for ((on, lab) in listOf(true to "Auto from RA", false to "Manual")) {
                                TextButton(onClick = { cfg = cfg.copy(routesAuto6 = on) }) {
                                    Text(
                                        lab,
                                        color = if (cfg.routesAuto6 == on) MaterialTheme.colorScheme.primary
                                        else MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                        OutlinedTextField(
                            value = cfg.manualRoutes6,
                            onValueChange = { cfg = cfg.copy(manualRoutes6 = it) },
                            label = { Text("Manual routes (addr/prefix, comma sep)") },
                            supportingText = {
                                Text(
                                    if (cfg.routesAuto6) "extra routes through the VPN"
                                    else "the only routes through the VPN; add ::/0 for a default",
                                )
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = cfg.ignoreRoutes6,
                            onValueChange = { cfg = cfg.copy(ignoreRoutes6 = it) },
                            label = { Text("Bypass routes (prefixes around the VPN)") },
                            supportingText = {
                                Text("everything else still goes through the default route")
                            },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Per-app routing", modifier = Modifier.weight(1f))
                    for ((key, lab) in listOf("off" to "Off", "allow" to "Only chosen", "block" to "Except chosen")) {
                        TextButton(onClick = {
                            appMode = key
                            persistApps(key, appSet)
                        }) {
                            Text(
                                lab,
                                color = if (appMode == key) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                if (appMode != "off") {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedButton(onClick = { showAppPicker = true }) {
                            Text("Chosen apps (${appSet.size})")
                        }
                        Text(
                            "applies on next connect",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = 8.dp),
                        )
                    }
                }

                val pm = context.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
                val ignoring = pm?.isIgnoringBatteryOptimizations(context.packageName) == true
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        if (ignoring) "Battery optimization: exempt"
                        else "Battery optimization: active",
                        modifier = Modifier.weight(1f),
                    )
                    if (!ignoring) {
                        TextButton(onClick = {
                            try {
                                val i = android.content.Intent(
                                    android.provider.Settings
                                        .ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                )
                                i.data = android.net.Uri.parse("package:${context.packageName}")
                                context.startActivity(i)
                            } catch (e: Exception) {
                                SeNative.lastError = "Battery settings unavailable: ${e.message}"
                            }
                        }) { Text("Exempt") }
                    }
                }
                }

                if (showAppPicker) {
                    val ownPackage = context.packageName
                    var query by remember { mutableStateOf("") }
                    var showSys by remember { mutableStateOf(prefs.getBoolean("showSysApps", false)) }
                    val allApps = remember { loadInstalledApps(context) }
                    val q = query.trim().lowercase()
                    val visible = allApps.filter {
                        (showSys || !it.third || it.first in appSet || it.first == ownPackage) &&
                            (q.isEmpty() || it.second.lowercase().contains(q) ||
                                it.first.lowercase().contains(q))
                    }
                    AlertDialog(
                        onDismissRequest = { showAppPicker = false },
                        title = {
                            Text(if (appMode == "allow") "Only these apps use the VPN"
                            else "These apps bypass the VPN")
                        },
                        text = {
                            Column {
                                OutlinedTextField(
                                    value = query,
                                    onValueChange = { query = it },
                                    placeholder = { Text("Search name or package") },
                                    singleLine = true,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(bottom = 4.dp),
                                )
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        "Show system apps",
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodyMedium,
                                    )
                                    Switch(
                                        checked = showSys,
                                        onCheckedChange = {
                                            showSys = it
                                            prefs.edit().putBoolean("showSysApps", it).apply()
                                        },
                                    )
                                }
                                Text(
                                    "${visible.size} shown, ${appSet.size} chosen",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                LazyColumn(modifier = Modifier.heightIn(max = 360.dp)) {
                                    items(visible) { app ->
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(app.second)
                                                Text(
                                                    app.first,
                                                    style = MaterialTheme.typography.bodySmall,
                                                )
                                            }
                                            Checkbox(
                                                checked = app.first in appSet,
                                                onCheckedChange = {
                                                    appSet = if (app.first in appSet) appSet - app.first
                                                    else appSet + app.first
                                                    persistApps(appMode, appSet)
                                                },
                                            )
                                        }
                                    }
                                }
                            }
                        },
                        confirmButton = {
                            TextButton(onClick = { showAppPicker = false }) { Text("Done") }
                        },
                    )
                }

                nameDlg?.let { dlg ->
                    AlertDialog(
                        onDismissRequest = {
                            nameDlg = null
                            pendingSrc = null
                        },
                        title = {
                            Text(if (dlg.first == "rename") "Rename profile" else "Profile name")
                        },
                        text = {
                            OutlinedTextField(
                                value = nameText,
                                onValueChange = { nameText = it },
                                label = { Text(dlg.second) },
                                supportingText = { Text("leave empty to use the auto name") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                if (pendingSrc != null) confirmCreate(nameText)
                                else applyProfileName(nameText, dlg.third)
                                nameDlg = null
                            }) { Text("OK") }
                        },
                        dismissButton = {
                            TextButton(
                                onClick = {
                                    nameDlg = null
                                    pendingSrc = null
                                },
                            ) { Text("Cancel") }
                        },
                    )
                }
            }
        }
    }
}
