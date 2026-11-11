package org.softether.android

import android.content.Context

// The display index of a profile is its id number ("p3" -> 3): never stored
// separately, never renumbered when other profiles are deleted, and new
// profiles reuse the lowest free number. Names alone may repeat; the "N: "
// prefix on the display name keeps them distinguishable.
data class ProfileEntry(val id: String, val name: String, val custom: Boolean)

// Multi-profile store, kept deliberately parse-free: the VpnEngine service
// process reads through loadCurrent() before native init has run, so this
// object must never touch SeNative.
object ProfileStore {
    private fun p(context: Context) =
        context.getSharedPreferences("profiles", Context.MODE_PRIVATE)

    private fun encode(e: ProfileEntry): String =
        e.id + "\t" + e.name + if (e.custom) "\tc" else ""

    fun all(context: Context): List<ProfileEntry> =
        (p(context).getString("list", "") ?: "").split('\n')
            .mapNotNull { line ->
                val parts = line.split('\t')
                if (parts.size >= 2 && parts[0].isNotEmpty())
                    ProfileEntry(parts[0], parts[1], parts.size >= 3 && parts[2] == "c")
                else
                    null
            }.sortedBy { num(it.id) }

    fun num(id: String): Int = id.removePrefix("p").toIntOrNull() ?: 0

    fun displayName(e: ProfileEntry): String = "${num(e.id)}: ${e.name}"

    fun save(context: Context, entries: List<ProfileEntry>, cur: String) {
        p(context).edit()
            .putString("list", entries.joinToString("\n") { encode(it) })
            .putString("cur", cur)
            .apply()
    }

    fun currentId(context: Context): String {
        ensureInitial(context)
        return p(context).getString("cur", "") ?: ""
    }

    fun cfgText(context: Context, id: String): String =
        p(context).getString("cfg_$id", "") ?: ""

    fun putCfg(context: Context, id: String, text: String) {
        p(context).edit().putString("cfg_$id", text).apply()
    }

    fun removeCfg(context: Context, id: String) {
        p(context).edit().remove("cfg_$id").apply()
    }

    // lowest free "p<N>" slot, including numbers freed by deletions
    fun newId(context: Context, existing: List<ProfileEntry> = all(context)): String {
        val used = existing.map { it.id }.toSet()
        var n = 1
        while ("p$n" in used) n++
        return "p$n"
    }

    // Rewrites ids as consecutive p1..pN in the given order (order key = the
    // index); names, custom flags, cfg texts and "cur" follow their profiles.
    fun reindex(context: Context, ordered: List<ProfileEntry>, cur: String): Pair<List<ProfileEntry>, String> {
        val texts = ordered.associate { it.id to cfgText(context, it.id) }
        val kept = ordered.mapIndexed { i, e -> ProfileEntry("p${i + 1}", e.name, e.custom) }
        val newCur = "p${ordered.indexOfFirst { it.id == cur }.coerceAtLeast(0) + 1}"
        val edit = p(context).edit()
        for (e in all(context)) {
            if (kept.none { it.id == e.id }) edit.remove("cfg_${e.id}")
        }
        kept.forEach { edit.putString("cfg_${it.id}", texts[ordered[kept.indexOf(it)].id] ?: "") }
        edit.putString("list", kept.joinToString("\n") { encode(it) })
        edit.putString("cur", newCur)
        edit.apply()
        return kept to newCur
    }

    fun defaultName(user: String?, host: String?): String =
        when {
            !user.isNullOrEmpty() && !host.isNullOrEmpty() -> "$user @ $host"
            !host.isNullOrEmpty() -> host
            !user.isNullOrEmpty() -> user
            else -> "Default"
        }

    fun ensureInitial(context: Context) {
        if (all(context).isEmpty()) {
            val legacy = context.getSharedPreferences("profile", Context.MODE_PRIVATE)
                .getString("cfg", "") ?: ""
            val e = ProfileEntry("p1", defaultName(null, null), custom = false)
            p(context).edit()
                .putString("list", encode(e))
                .putString("cur", "p1")
                .apply()
            if (legacy.isNotEmpty() && cfgText(context, "p1").isEmpty()) {
                putCfg(context, "p1", legacy)
            }
        }
    }

    fun loadCurrent(context: Context): String {
        ensureInitial(context)
        val id = p(context).getString("cur", "") ?: ""
        return cfgText(context, id).ifEmpty {
            context.getSharedPreferences("profile", Context.MODE_PRIVATE)
                .getString("cfg", "") ?: ""
        }
    }
}
