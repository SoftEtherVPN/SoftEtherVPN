package org.softether.android

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

// The profile picker menu; every callback runs after the menu has closed, and
// callers keep their own savePrefs() sequencing.
@Composable
internal fun ProfileMenu(
    entries: List<ProfileEntry>,
    curId: String,
    busy: Boolean,
    expanded: Boolean,
    onDismiss: () -> Unit,
    onSwitch: (String) -> Unit,
    onNew: () -> Unit,
    onDuplicate: () -> Unit,
    onImport: () -> Unit,
    onExport: () -> Unit,
    onRename: () -> Unit,
    onMove: (Int) -> Unit,
    onDelete: () -> Unit,
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        entries.forEach { e ->
            DropdownMenuItem(
                text = { Text((if (e.id == curId) "◉ " else "○  ") + ProfileStore.displayName(e)) },
                onClick = { onDismiss(); onSwitch(e.id) },
            )
        }
        Divider()
        DropdownMenuItem(
            text = { Text("New profile") },
            onClick = { onDismiss(); onNew() },
        )
        DropdownMenuItem(
            text = { Text("Duplicate current") },
            onClick = { onDismiss(); onDuplicate() },
        )
        DropdownMenuItem(
            text = { Text("Import account file") },
            onClick = { onDismiss(); onImport() },
        )
        DropdownMenuItem(
            text = { Text("Export current") },
            onClick = { onDismiss(); onExport() },
        )
        DropdownMenuItem(
            text = { Text("Rename current") },
            enabled = !busy,
            onClick = { onDismiss(); onRename() },
        )
        DropdownMenuItem(
            text = { Text("Move up") },
            onClick = { onDismiss(); onMove(-1) },
        )
        DropdownMenuItem(
            text = { Text("Move down") },
            onClick = { onDismiss(); onMove(1) },
        )
        DropdownMenuItem(
            text = { Text("Delete current") },
            enabled = !busy,
            onClick = { onDismiss(); onDelete() },
        )
    }
}

@Composable
internal fun NameDialog(
    mode: String,
    autoName: String,
    nameText: String,
    onNameText: (String) -> Unit,
    onOk: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(if (mode == "rename") "Rename profile" else "Profile name")
        },
        text = {
            OutlinedTextField(
                value = nameText,
                onValueChange = onNameText,
                label = { Text(autoName) },
                supportingText = { Text("leave empty to use the auto name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(onClick = { onOk(nameText) }) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
