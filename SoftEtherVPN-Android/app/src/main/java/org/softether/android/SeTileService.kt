package org.softether.android

import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

// Quick Settings tile: no per-profile binding (a tile cannot carry one), so it
// acts on the currently default-selected profile only — tap toggles that
// profile; a lit tile means an attempt is in flight or established, the icon
// disambiguates: full-color steady = connected, full-color ↔ dimmed blink =
// connecting. A press while connecting aborts it.
//
// ColorOS SystemUI ignores requestListeningState pushes, so the tile polls its
// own state every 500 ms while the shade is open (updateTile only on change).
class SeTileService : TileService() {

    private val handler = Handler(Looper.getMainLooper())
    private var polling = false
    private var blinkOn = true
    private var lastKey = ""

    private val pollRunnable = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, POLL_MS)
        }
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val curId = ProfileStore.currentId(this)
        val entry = ProfileStore.all(this).find { it.id == curId }
            ?: ProfileEntry(curId, "Default", false)
        val label = ProfileStore.displayName(entry)
        val st = VpnState.of(curId)
        blinkOn = if (st == VpnState.CONNECTING) !blinkOn else true
        val iconRes = when (st) {
            VpnState.CONNECTED -> R.drawable.ic_state_connected
            VpnState.CONNECTING ->
                if (blinkOn) R.drawable.ic_state_connecting else R.drawable.ic_state_connecting_dim
            else -> R.drawable.ic_state_disconnected
        }
        // lit (ACTIVE) while connecting too, so SystemUI's optimistic flip after
        // a tap matches our truth; the blinking icon is the in-flight signal
        val state = if (st == VpnState.DISCONNECTED) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        val key = "$label|$state|$iconRes"
        if (key != lastKey) {
            lastKey = key
            tile.label = label
            tile.state = state
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                tile.setIcon(android.graphics.drawable.Icon.createWithResource(packageName, iconRes))
            }
            tile.updateTile()
        }
    }

    override fun onStartListening() {
        polling = true
        blinkOn = true
        refresh()
        handler.removeCallbacks(pollRunnable)
        handler.postDelayed(pollRunnable, POLL_MS)
    }

    override fun onStopListening() {
        polling = false
        handler.removeCallbacks(pollRunnable)
    }

    override fun onClick() {
        val curId = ProfileStore.currentId(this)
        if (SeNative.activeProfileId.isNotEmpty() && SeNative.activeProfileId == curId) {
            startService(Intent(this, VpnEngine::class.java).setAction(VpnEngine.ACTION_STOP))
        } else {
            ContextCompat.startForegroundService(
                this,
                Intent(this, VpnEngine::class.java)
                    .setAction(VpnEngine.ACTION_CONNECT)
                    .putExtra(VpnEngine.EXTRA_CFG, ProfileStore.loadCurrent(this))
                    .putExtra(VpnEngine.EXTRA_PROFILE, curId),
            )
        }
        lastKey = ""
        refresh()
        if (!polling) {
            polling = true
            handler.postDelayed(pollRunnable, POLL_MS)
        }
    }

    companion object {
        private const val POLL_MS = 500L
    }
}
