package org.softether.android

// Pure status-text formatting shared by the main screen and the status surfaces.

internal fun formatConnInfo(info: Array<String>?): String {
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

// Split-family awareness in the phase wording: when one family is configured
// while the other is still applying, name the pending one. The acquired
// addresses belong on the assigned-IP line (see the poller), not in the status text.
internal fun statusLine(phase: String, ip4: String, ip6: String): String {
    if (phase.startsWith("Connected")) return phase

    val joint = phase.startsWith("Applying IPv4/IPv6 configuration")
    return when {
        joint && ip4.isNotEmpty() && ip6.isEmpty() ->
            "Applying IPv6 configuration (waiting for router advertisement)..."
        joint && ip6.isNotEmpty() && ip4.isEmpty() ->
            "Applying IPv4 configuration..."
        else -> phase
    }
}

internal fun acquiredIp4(h: Long): String =
    runCatching { SeNative.nativeGetIPv4Info(h) }.getOrNull()?.getOrNull(0).orEmpty()

internal fun acquiredIp6(h: Long): String =
    runCatching { SeNative.nativeGetIPv6Config(h) }.getOrNull()?.getOrNull(0).orEmpty()
