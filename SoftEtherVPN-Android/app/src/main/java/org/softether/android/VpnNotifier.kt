package org.softether.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build

// Foreground notification and its channel, plus the state broadcast consumed by
// the widget and the QS tile refresh.
internal object VpnNotifier {
    const val CHANNEL_ID = "vpn"
    const val NOTIFICATION_ID = 2

    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    fun ensureChannel(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    fun build(context: Context, text: String): Notification {
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val content = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            flags,
        )
        val stop = PendingIntent.getService(
            context, 1,
            Intent(context, VpnEngine::class.java).setAction(VpnEngine.ACTION_STOP),
            flags,
        )
        return Notification.Builder(context, CHANNEL_ID)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setContentIntent(content)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stop)
            .build()
    }

    fun notifyText(context: Context, text: String) {
        runCatching {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFICATION_ID, build(context, text))
        }
    }

    fun broadcastState(context: Context) {
        runCatching {
            context.sendBroadcast(
                Intent(VpnEngine.ACTION_STATE_CHANGED).setPackage(context.packageName),
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            mainHandler.post {
                runCatching {
                    android.service.quicksettings.TileService.requestListeningState(
                        context,
                        android.content.ComponentName(context, SeTileService::class.java),
                    )
                }
            }
        }
    }
}
