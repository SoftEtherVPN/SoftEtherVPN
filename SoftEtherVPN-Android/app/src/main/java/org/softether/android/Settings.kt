package org.softether.android

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings as AndroidSettings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

private const val APP_MODE_OFF = "off"
private const val APP_MODE_ALLOW = "allow"

private val APP_MODES = listOf(
    "off" to "Off",
    "allow" to "Only chosen",
    "block" to "Except chosen",
)

// Chosen apps bypass the VPN when the mode is "block"
private fun appPickerTitle(appMode: String): String =
    if (appMode == APP_MODE_ALLOW) "Only these apps use the VPN"
    else "These apps bypass the VPN"

private fun formatLabel(app: Triple<String, String, Boolean>): String = app.second

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
            .sortedBy { it.second.lowercase() }
    } catch (e: Exception) {
        emptyList()
    }
}

// Full-screen configuration page; every piece of state is hoisted to App()
@Composable
fun SettingsScreen(
    cfg: SeConfig,
    onCfg: (SeConfig) -> Unit,
    raw: String,
    onRaw: (String) -> Unit,
    rawMode: Boolean,
    onRawMode: (Boolean) -> Unit,
    appMode: String,
    appSet: Set<String>,
    onAppMode: (String) -> Unit,
    onShowAppPicker: (Boolean) -> Unit,
    onBack: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Text(
                "Configuration",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(start = 8.dp),
            )
        }

        Text("Advanced configuration (raw)", modifier = Modifier.padding(top = 8.dp))
        Switch(checked = rawMode, onCheckedChange = onRawMode)

        if (rawMode) {
            OutlinedTextField(
                value = raw,
                onValueChange = onRaw,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                minLines = 8,
            )
            OutlinedButton(
                onClick = {
                    onRaw(
                        try {
                            SeNative.nativeCfgDefault("Android VPN Account")
                        } catch (e: Exception) {
                            SeNative.lastError = "CFG unavailable: ${e.message}"
                            raw
                        }
                    )
                },
            ) { Text("Load default CFG account") }
        } else {
            SwitchRow("Encrypt", cfg.encrypt) { onCfg(cfg.copy(encrypt = it)) }
            SwitchRow("Compress", cfg.compress) { onCfg(cfg.copy(compress = it)) }
            SwitchRow("Verify server cert", cfg.checkServerCert) {
                onCfg(cfg.copy(checkServerCert = it))
            }
            SwitchRow("IPv4", cfg.useIpv4) { onCfg(cfg.copy(useIpv4 = it)) }
            if (cfg.useIpv4) {
                SwitchRow("IPv4 via DHCP", cfg.dhcp) { onCfg(cfg.copy(dhcp = it)) }
                if (!cfg.dhcp) {
                    LabeledField("Static IP", cfg.staticIp) { onCfg(cfg.copy(staticIp = it)) }
                    LabeledField("Subnet mask", cfg.staticMask) { onCfg(cfg.copy(staticMask = it)) }
                    LabeledField("Gateway", cfg.staticGw) { onCfg(cfg.copy(staticGw = it)) }
                    LabeledField("DNS 1", cfg.dns1) { onCfg(cfg.copy(dns1 = it)) }
                    LabeledField("DNS 2", cfg.dns2) { onCfg(cfg.copy(dns2 = it)) }
                }
                RoutePickerRow(
                    label = "IPv4 routes:",
                    autoLabel = "Auto from DHCP",
                    auto = cfg.routesAuto4,
                    onAuto = { onCfg(cfg.copy(routesAuto4 = it)) },
                )
                OutlinedTextField(
                    value = cfg.manualRoutes4,
                    onValueChange = { onCfg(cfg.copy(manualRoutes4 = it)) },
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
                    onValueChange = { onCfg(cfg.copy(ignoreRoutes4 = it)) },
                    label = { Text("Bypass routes (prefixes around the VPN)") },
                    supportingText = { Text("everything else still goes through the default route") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            SwitchRow("IPv6", cfg.useIpv6) { onCfg(cfg.copy(useIpv6 = it)) }
            if (cfg.useIpv6) {
                SwitchRow("IPv6 via router RA", cfg.ra6) { onCfg(cfg.copy(ra6 = it)) }
                if (!cfg.ra6) {
                    LabeledField("Static IPv6 (e.g. 2001:db8::2)", cfg.staticIpv6) {
                        onCfg(cfg.copy(staticIpv6 = it))
                    }
                    LabeledField("Prefix length (64)", cfg.staticMask6) {
                        onCfg(cfg.copy(staticMask6 = it))
                    }
                    LabeledField("Gateway (link-local ok)", cfg.staticGw6) {
                        onCfg(cfg.copy(staticGw6 = it))
                    }
                }
                LabeledField("DNS (IPv6, optional)", cfg.dns6) { onCfg(cfg.copy(dns6 = it)) }
                RoutePickerRow(
                    label = "IPv6 routes:",
                    autoLabel = "Auto from RA",
                    auto = cfg.routesAuto6,
                    onAuto = { onCfg(cfg.copy(routesAuto6 = it)) },
                )
                OutlinedTextField(
                    value = cfg.manualRoutes6,
                    onValueChange = { onCfg(cfg.copy(manualRoutes6 = it)) },
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
                    onValueChange = { onCfg(cfg.copy(ignoreRoutes6 = it)) },
                    label = { Text("Bypass routes (prefixes around the VPN)") },
                    supportingText = { Text("everything else still goes through the default route") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Per-app routing", modifier = Modifier.weight(1f))
            for ((key, lab) in APP_MODES) {
                TextButton(onClick = { onAppMode(key) }) {
                    Text(
                        lab,
                        color = if (appMode == key) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        if (appMode != APP_MODE_OFF) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(onClick = { onShowAppPicker(true) }) {
                    Text("Chosen apps (${appSet.size})")
                }
                Text(
                    "applies on next connect",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }

        BatteryOptOutRow()
    }
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun LabeledField(label: String, value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun RoutePickerRow(
    label: String,
    autoLabel: String,
    auto: Boolean,
    onAuto: (Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f))
        for ((on, lab) in listOf(true to autoLabel, false to "Manual")) {
            TextButton(onClick = { onAuto(on) }) {
                Text(
                    lab,
                    color = if (auto == on) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun BatteryOptOutRow() {
    val context = LocalContext.current
    val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
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
                    val i = Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    i.data = Uri.parse("package:${context.packageName}")
                    context.startActivity(i)
                } catch (e: Exception) {
                    SeNative.lastError = "Battery settings unavailable: ${e.message}"
                }
            }) { Text("Exempt") }
        }
    }
}

@Composable
fun AppPickerDialog(
    prefs: SharedPreferences,
    appMode: String,
    appSet: Set<String>,
    onAppSet: (Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val ownPackage = context.packageName
    var query by remember { mutableStateOf("") }
    var showSys by remember { mutableStateOf(prefs.getBoolean("showSysApps", false)) }
    // order is fixed when the dialog opens: chosen apps first (as chosen then),
    // then the rest by name; our own app can never be chosen
    val ordered = remember {
        val chosenAtOpen = appSet.toSet()
        loadInstalledApps(context)
            .filter { it.first != ownPackage || it.first in chosenAtOpen }
            .sortedWith(compareBy({ it.first !in chosenAtOpen }, { it.second.lowercase() }))
    }
    val q = query.trim().lowercase()
    val visible = ordered.filter {
        (showSys || !it.third || it.first in appSet) &&
            (q.isEmpty() || it.second.lowercase().contains(q) || it.first.lowercase().contains(q))
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(appPickerTitle(appMode)) },
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
                                Text(formatLabel(app))
                                Text(app.first, style = MaterialTheme.typography.bodySmall)
                            }
                            Checkbox(
                                checked = app.first in appSet,
                                onCheckedChange = {
                                    onAppSet(
                                        if (app.first in appSet) appSet - app.first
                                        else appSet + app.first
                                    )
                                },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
    )
}
