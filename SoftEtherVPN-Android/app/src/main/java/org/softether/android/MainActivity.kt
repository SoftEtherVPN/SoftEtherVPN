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
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { App() }
    }
}

private fun startVpn(context: Context, cfgText: String, profileId: String) {
    val i = Intent(context, VpnEngine::class.java)
    i.action = VpnEngine.ACTION_CONNECT
    i.putExtra(VpnEngine.EXTRA_CFG, cfgText)
    i.putExtra(VpnEngine.EXTRA_PROFILE, profileId)
    ContextCompat.startForegroundService(context, i)
}

// Durable state and flows live in AppViewModel; this composable keeps only the
// transient dialog/navigation visibility, the activity launchers and the UI tree.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun App() {
    val context = LocalContext.current
    val vm: AppViewModel = viewModel()

    var showConfig by rememberSaveable { mutableStateOf(false) }
    var profilesMenu by remember { mutableStateOf(false) }
    var showAppPicker by remember { mutableStateOf(false) }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> vm.onImportResult(uri) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.openOutputStream(uri)?.use {
                    it.write(vm.effectiveCfg().toByteArray(Charsets.UTF_8))
                }
            } catch (e: Exception) {
                SeNative.lastError = "Export failed: ${e.message}"
            }
        }
    }

    // debounced form autosave
    LaunchedEffect(vm.rawMode, vm.cfg, vm.raw) {
        delay(300)
        vm.savePrefs()
        vm.refreshAutoName()
    }

    val vpnPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            startVpn(context, vm.effectiveCfg(), vm.curId)
        }
    }

    val androidVerLabel = remember(context) {
        val vi = context.packageManager.getPackageInfo(context.packageName, 0)
        "Android vc${vi.longVersionCode}"
    }

    MaterialTheme {
        BackHandler(enabled = showConfig) { showConfig = false }

        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Column {
                            Text(stringResource(R.string.app_name))
                            Text("ver ${vm.coreVer.ifEmpty { "…" }} · $androidVerLabel",
                                style = MaterialTheme.typography.bodySmall)
                        }
                    },
                )
            },
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .imePadding()
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (!showConfig) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = vm.entries.find { it.id == vm.curId }
                                ?.let { ProfileStore.displayName(it) } ?: "1: Default",
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.weight(1f),
                        )
                        Box {
                            TextButton(onClick = {
                                vm.refreshEntries()
                                profilesMenu = true
                            }) { Text("Profiles") }
                            ProfileMenu(
                                entries = vm.entries,
                                curId = vm.curId,
                                busy = vm.busy,
                                expanded = profilesMenu,
                                onDismiss = { profilesMenu = false },
                                onSwitch = { id ->
                                    vm.savePrefs()
                                    vm.switchProfile(id)
                                },
                                onNew = {
                                    vm.savePrefs()
                                    vm.beginCreate("new", "")
                                },
                                onDuplicate = {
                                    vm.savePrefs()
                                    vm.beginCreate("dup", ProfileStore.cfgText(context, vm.curId))
                                },
                                onImport = {
                                    vm.savePrefs()
                                    importLauncher.launch(
                                        arrayOf("application/octet-stream", "text/plain"),
                                    )
                                },
                                onExport = {
                                    vm.savePrefs()
                                    val fn = (vm.entries.find { it.id == vm.curId }?.name ?: "profile")
                                        .replace(Regex("""[\\/:*?"<>|]"""), "_") + ".vpn"
                                    exportLauncher.launch(fn)
                                },
                                onRename = { vm.openNameDlg("rename", vm.curId) },
                                onMove = { dir ->
                                    vm.savePrefs()
                                    vm.moveCurrent(dir)
                                },
                                onDelete = {
                                    vm.savePrefs()
                                    vm.deleteCurrent()
                                },
                            )
                        }
                    }

                    Text("Status: ${vm.statusText}")

                    if (vm.connInfo.isNotEmpty()) {
                        Text(
                            text = vm.connInfo,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            enabled = !vm.busy,
                            onClick = {
                                vm.savePrefs()
                                val prep = VpnService.prepare(context)
                                if (prep != null) {
                                    vpnPermission.launch(prep)
                                } else {
                                    startVpn(context, vm.effectiveCfg(), vm.curId)
                                }
                            },
                        ) { Text("Connect") }
                        OutlinedButton(
                            enabled = vm.sessionAlive,
                            onClick = {
                                val i = Intent(context, VpnEngine::class.java)
                                i.action = VpnEngine.ACTION_STOP
                                context.startService(i)
                            },
                        ) { Text("Disconnect") }
                    }

                    OutlinedTextField(
                        value = vm.cfg.host,
                        onValueChange = { vm.cfg = vm.cfg.copy(host = it) },
                        label = { Text("Server address") },
                        singleLine = true,
                        readOnly = vm.rawMode,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = vm.portStr,
                        onValueChange = {
                            val digits = it.filter(Char::isDigit)
                            vm.portStr = digits
                            vm.cfg = vm.cfg.copy(port = digits.toIntOrNull() ?: 0)
                        },
                        label = { Text("Port") },
                        singleLine = true,
                        readOnly = vm.rawMode,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = vm.cfg.hub,
                        onValueChange = { vm.cfg = vm.cfg.copy(hub = it) },
                        label = { Text("Virtual Hub") },
                        singleLine = true,
                        readOnly = vm.rawMode,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = vm.cfg.user,
                        onValueChange = { vm.cfg = vm.cfg.copy(user = it) },
                        label = { Text("Username") },
                        singleLine = true,
                        readOnly = vm.rawMode,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = vm.cfg.pass ?: "",
                        onValueChange = { vm.cfg = vm.cfg.copy(pass = it) },
                        label = { Text(if (vm.cfg.pass == null) "Password (stored hashed)" else "Password") },
                        singleLine = true,
                        readOnly = vm.rawMode,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    if (vm.rawMode) {
                        Text(
                            "Raw configuration mode is active — edit it on the configuration screen.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    OutlinedButton(onClick = { showConfig = true }) { Text("Configuration…") }
                } else {
                    SettingsScreen(
                        cfg = vm.cfg,
                        onCfg = { vm.cfg = it },
                        raw = vm.raw,
                        onRaw = { vm.raw = it },
                        rawMode = vm.rawMode,
                        onRawMode = { vm.onRawMode(it) },
                        appMode = vm.appMode,
                        appSet = vm.appSet,
                        onAppMode = { vm.onAppMode(it) },
                        onShowAppPicker = { showAppPicker = it },
                        onBack = { showConfig = false },
                    )
                }

                if (showAppPicker) {
                    AppPickerDialog(
                        prefs = vm.prefs,
                        appMode = vm.appMode,
                        appSet = vm.appSet,
                        onAppSet = { vm.onAppSet(it) },
                        onDismiss = { showAppPicker = false },
                    )
                }

                vm.nameDlg?.let { dlg ->
                    NameDialog(
                        mode = dlg.first,
                        autoName = dlg.second,
                        nameText = vm.nameText,
                        onNameText = { vm.nameText = it },
                        onOk = { n ->
                            if (vm.pendingSrc != null) vm.confirmCreate(n)
                            else vm.applyProfileName(n, dlg.third)
                            vm.nameDlg = null
                        },
                        onDismiss = {
                            vm.nameDlg = null
                            vm.pendingSrc = null
                        },
                    )
                }
            }
        }
    }
}
