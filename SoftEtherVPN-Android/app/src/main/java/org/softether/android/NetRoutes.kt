package org.softether.android

import android.net.InetAddresses
import android.util.Log
import java.math.BigInteger

// Pure prefix/route math shared by the connect flow's traffic-route plumbing.

internal class Net46(val addr: BigInteger, val plen: Int, val bits: Int)

internal val netV4Default = Net46(BigInteger.ZERO, 0, 32)
internal val netV6Default = Net46(BigInteger.ZERO, 0, 128)

internal fun prefixFromMask(mask: String): Int {
    var bits = 0
    mask.split(".").forEach { bits += Integer.bitCount((it.toIntOrNull() ?: 0) and 0xFF) }
    return bits.coerceIn(0, 32)
}

// comma-separated "addr/prefix" list (bare addr = host route), family-checked
internal fun parseNetList(s: String, v6: Boolean): List<Net46> {
    val bits = if (v6) 128 else 32
    val out = ArrayList<Net46>()
    for (raw in s.split(',', ';', ' ', '\n', '\r', '\t')) {
        val e = raw.trim()
        if (e.isEmpty()) continue
        val sl = e.indexOf('/')
        val addrStr = if (sl >= 0) e.substring(0, sl) else e
        val plen = if (sl >= 0) e.substring(sl + 1).toIntOrNull() else if (v6) 128 else 32
        if (plen == null || plen < 0 || plen > bits) continue
        val a = try {
            InetAddresses.parseNumericAddress(addrStr)
        } catch (e2: Exception) {
            Log.w("SETH", "route entry skip '$e'")
            null
        } ?: continue
        if ((v6 && a !is java.net.Inet6Address) || (!v6 && a !is java.net.Inet4Address)) {
            Log.w("SETH", "route entry family mismatch '$e'")
            continue
        }
        var bi = BigInteger.ZERO
        for (b in a.address) {
            bi = bi.shiftLeft(8).or(BigInteger.valueOf((b.toInt() and 0xFF).toLong()))
        }
        out.add(Net46(bi, plen, bits))
    }
    return out
}

internal fun netContains(outer: Net46, inner: Net46): Boolean =
    outer.bits == inner.bits && outer.plen <= inner.plen &&
        outer.addr.shiftRight(outer.bits - outer.plen) == inner.addr.shiftRight(outer.bits - outer.plen)

internal fun netOverlaps(a: Net46, b: Net46): Boolean {
    if (a.bits != b.bits) return false
    val m = minOf(a.plen, b.plen)
    return a.addr.shiftRight(a.bits - m) == b.addr.shiftRight(b.bits - m)
}

// prefix space covered by 'prefix' minus every prefix in 'ignores',
// expressed as a minimal-ish list of subnet prefixes (binary split)
internal fun netSubtract(prefix: Net46, ignores: List<Net46>, cap: Int): List<Net46> {
    var cur = listOf(prefix)
    for (ig in ignores) {
        while (true) {
            val idx = cur.indexOfFirst { netOverlaps(it, ig) }
            if (idx < 0) break
            val p = cur[idx]
            val rest = ArrayList(cur)
            rest.removeAt(idx)
            if (ig.plen <= p.plen) {
                cur = rest // ignore fully covers p
                continue
            }
            val childPlen = p.plen + 1
            if (childPlen > p.bits) {
                cur = rest
                continue
            }
            rest.add(Net46(p.addr, childPlen, p.bits))
            rest.add(
                Net46(
                    p.addr.add(BigInteger.ONE.shiftLeft(p.bits - childPlen)),
                    childPlen, p.bits,
                ),
            )
            cur = rest
            if (cur.size > cap) break
        }
    }
    return cur
}

internal fun bigToIp(bi: BigInteger, bits: Int): String? {
    return try {
        val len = bits / 8
        val src = bi.toByteArray()
        val bytes = ByteArray(len)
        for (i in 0 until len) {
            val si = src.size - len + i
            if (si >= 0) bytes[i] = src[si]
        }
        java.net.InetAddress.getByAddress(bytes).hostAddress
    } catch (e: Exception) {
        null
    }
}
