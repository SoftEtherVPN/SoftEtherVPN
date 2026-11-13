package org.softether.android

// Tri-state connection view for a given profile (widgets / QS tile) — derived
// purely from the SeNative engine fields, so no Mayaqua call ever happens in a
// widget receiver process.
object VpnState {
    const val DISCONNECTED = 0
    const val CONNECTING = 1
    const val CONNECTED = 2

    fun connectedNow(): Boolean =
        SeNative.handle != 0L && SeNative.negotiatedIp.isNotEmpty()

    fun of(profileId: String): Int = when {
        profileId.isEmpty() || SeNative.activeProfileId != profileId -> DISCONNECTED
        connectedNow() -> CONNECTED
        else -> CONNECTING
    }
}
