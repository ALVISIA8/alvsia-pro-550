package com.alvsia.pro.sec

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Local tactical status notifications. Separate from owner-side Telegram delivery.
 * Never includes license keys, session tokens, or HWIDs.
 */
object TacticalNotifier {
    private const val CHANNEL_ID = "alvisia_operations"
    private const val CHANNEL_NAME = "ALVISIA Operations"

    fun post(context: Context, title: String, detail: String, eventId: Int = 550) {
        try {
            if (Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) return

            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        CHANNEL_NAME,
                        NotificationManager.IMPORTANCE_DEFAULT
                    ).apply {
                        description = "ALVISIA PRO login, tool and security status"
                        setShowBadge(true)
                    }
                )
            }

            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                android.app.Notification.Builder(context, CHANNEL_ID)
            } else {
                @Suppress("DEPRECATION")
                android.app.Notification.Builder(context)
            }
            val notification = builder
                .setSmallIcon(context.applicationInfo.icon)
                .setContentTitle("ALVISIA PRO // $title")
                .setContentText(detail.take(180))
                .setStyle(android.app.Notification.BigTextStyle().bigText(detail.take(500)))
                .setCategory(android.app.Notification.CATEGORY_STATUS)
                .setAutoCancel(true)
                .build()
            manager.notify(eventId, notification)
        } catch (_: SecurityException) {
            // Permission can be revoked between check and post.
        } catch (_: Exception) {
            // Notifications must never interrupt a tool operation.
        }
    }
}
