package org.softether.android

import android.app.Activity
import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.RemoteViews
import androidx.core.content.ContextCompat

// 1x1 widget: each instance is bound (at add time, via WidgetConfigActivity)
// to one profile and shows that profile's tri-state. Press toggles that
// profile; the widget never changes the app's selected profile.
class VpnWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        for (id in ids) VpnWidgetProvider.updateWidget(context, manager, id)
    }

    override fun onDeleted(context: Context, ids: IntArray) {
        val ed = context.getSharedPreferences("widgets", Context.MODE_PRIVATE).edit()
        for (id in ids) ed.remove("wid_$id")
        ed.apply()
    }

    override fun onDisabled(context: Context) {
        val p = context.getSharedPreferences("widgets", Context.MODE_PRIVATE)
        val ed = p.edit()
        for (k in p.all.keys) if (k.startsWith("wid_")) ed.remove(k)
        ed.apply()
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        when (intent.action) {
            ACTION_TOGGLE -> toggleWidget(context, intent.getIntExtra(EXTRA_WIDGET_ID, -1))
            VpnEngine.ACTION_STATE_CHANGED -> {
                val manager = AppWidgetManager.getInstance(context) ?: return
                onUpdate(
                    context, manager,
                    manager.getAppWidgetIds(ComponentName(context, VpnWidgetProvider::class.java)),
                )
            }
        }
    }

    companion object {
        const val ACTION_TOGGLE = "org.softether.android.action.WIDGET_TOGGLE"
        const val EXTRA_WIDGET_ID = "widget_id"

        private fun prefs(c: Context) = c.getSharedPreferences("widgets", Context.MODE_PRIVATE)

        // bound profile id; unset or deleted profile falls back to the app's
        // current selection (widgets never go dead)
        private fun profileIdFor(context: Context, widgetId: Int): String {
            val id = prefs(context).getString("wid_$widgetId", "") ?: ""
            return if (id.isNotEmpty() && ProfileStore.all(context).any { it.id == id }) id
            else ProfileStore.currentId(context)
        }

        fun updateWidget(context: Context, manager: AppWidgetManager, widgetId: Int) {
            val pid = profileIdFor(context, widgetId)
            val entry = ProfileStore.all(context).find { it.id == pid }
                ?: ProfileEntry(pid, "Default", false)
            val views = RemoteViews(context.packageName, R.layout.widget_vpn)
            val name = ProfileStore.displayName(entry)
            views.setTextViewText(R.id.widgetName, name)
            when (VpnState.of(pid)) {
                VpnState.CONNECTED -> {
                    views.setImageViewResource(R.id.widgetIcon, R.drawable.ic_state_connected)
                    views.setContentDescription(R.id.widgetRoot, "$name: " + context.getString(R.string.widget_connected))
                }
                VpnState.CONNECTING -> {
                    views.setImageViewResource(R.id.widgetIcon, R.drawable.ic_state_connecting)
                    views.setContentDescription(R.id.widgetRoot, "$name: " + context.getString(R.string.widget_connecting))
                }
                else -> {
                    views.setImageViewResource(R.id.widgetIcon, R.drawable.ic_state_disconnected)
                    views.setContentDescription(R.id.widgetRoot, "$name: " + context.getString(R.string.widget_disconnected))
                }
            }
            val tap = Intent(context, VpnWidgetProvider::class.java)
                .setAction(ACTION_TOGGLE)
                .putExtra(EXTRA_WIDGET_ID, widgetId)
                .setData(Uri.parse("sevpn://widget/$widgetId"))
            views.setOnClickPendingIntent(
                R.id.widgetRoot,
                PendingIntent.getBroadcast(
                    context, widgetId, tap,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
            manager.updateAppWidget(widgetId, views)
        }

        private fun toggleWidget(context: Context, widgetId: Int) {
            if (widgetId < 0) return
            val pid = profileIdFor(context, widgetId)
            if (SeNative.activeProfileId.isNotEmpty() && SeNative.activeProfileId == pid) {
                context.startService(Intent(context, VpnEngine::class.java).setAction(VpnEngine.ACTION_STOP))
            } else {
                val cfg = ProfileStore.cfgText(context, pid).ifEmpty { ProfileStore.loadCurrent(context) }
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, VpnEngine::class.java)
                        .setAction(VpnEngine.ACTION_CONNECT)
                        .putExtra(VpnEngine.EXTRA_CFG, cfg)
                        .putExtra(VpnEngine.EXTRA_PROFILE, pid),
                )
            }
        }
    }
}

// Profile picker shown when the widget is placed: binds the instance to the
// picked profile; back/cancel accepts and binds to the current selection.
class WidgetConfigActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val widgetId = intent?.extras?.getInt(AppWidgetManager.EXTRA_APPWIDGET_ID, -1) ?: -1
        val result = Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
        if (widgetId < 0) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        setResult(RESULT_OK, result)
        title = getString(R.string.widget_pick_profile)
        val entries = ProfileStore.all(this)
        val list = ListView(this)
        list.id = android.R.id.list
        list.adapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_1,
            entries.map { ProfileStore.displayName(it) },
        )
        list.setOnItemClickListener { _, _, pos, _ ->
            getSharedPreferences("widgets", Context.MODE_PRIVATE).edit()
                .putString("wid_$widgetId", entries[pos].id).commit()
            AppWidgetManager.getInstance(this)?.let {
                VpnWidgetProvider.updateWidget(this, it, widgetId)
            }
            finish()
        }
        setContentView(list)
    }
}
