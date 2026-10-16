package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import android.util.Log
import com.alvsia.pro.panel.Hwid
import com.alvsia.pro.panel.Vault
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Telegram owner alerts for important ALVISIA PRO events.
 * Uses Telegram HTML parse mode so user-provided detail cannot break MarkdownV2.
 * Delivery failures are recorded locally; notification delivery never blocks tools.
 */
object TelegramNotifier {
    private const val TAG = "ALVISIA_Telegram"
    private const val TG_API = "https://api.telegram.org/bot"

    private val http by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    private val icons = mapOf(
        "SESSION_OK" to "✅",
        "TOOL_OK" to "🟢",
        "TOOL_ERROR" to "🟠",
        "TAMPER" to "🚨",
        "FRIDA" to "🔴",
        "ROOT" to "⚠️",
        "DEBUG" to "🔶",
        "SIG_BLOCK" to "🛑",
        "ENGINE_CAP" to "🔷",
        "THREAT" to "🚨"
    )

    fun notify(ctx: Context, kind: String, detail: String = "", license: String = "") {
        if (kind !in NOTIFY_EVENTS) return

        val token = Vault.tgToken().trim()
        val chatId = Vault.tgChatId().trim()
        if (token.isBlank() || chatId.isBlank()) {
            Log.w(TAG, "Telegram not configured; event=$kind")
            return
        }

        // Snapshot safe metadata before dispatching to the worker.
        val appContext = ctx.applicationContext
        thread(name = "alvisia-telegram", isDaemon = true) {
            try {
                val hwid = runCatching { Hwid.deviceId(appContext).take(16) }.getOrDefault("unavailable")
                val model = "${Build.MANUFACTURER} ${Build.MODEL}".take(48)
                val keyMask = when {
                    license.length >= 8 -> license.take(4) + "****" + license.takeLast(4)
                    license.isNotBlank() -> "****"
                    else -> "not supplied"
                }
                val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
                val safeDetail = detail.take(240).ifBlank { "No additional details" }

                val message = buildString {
                    append("<b>").append(icons[kind] ?: "ℹ️")
                    append(" ALVISIA PRO // ").append(html(kind)).append("</b>\n")
                    append("<code>").append(html(ts)).append("</code>\n\n")
                    append("🔑 Key: <code>").append(html(keyMask)).append("</code>\n")
                    append("📱 Device: <code>").append(html(model)).append("</code> (SDK ")
                        .append(Build.VERSION.SDK_INT).append(")\n")
                    append("🔐 HWID: <code>").append(html(hwid)).append("…</code>\n")
                    append("📋 Detail: <code>").append(html(safeDetail)).append("</code>\n")
                    append("📦 Package: <code>").append(html(appContext.packageName)).append("</code>")
                }

                val payload = JSONObject()
                    .put("chat_id", chatId)
                    .put("text", message)
                    .put("parse_mode", "HTML")
                    .put("disable_notification", kind == "SESSION_OK")
                    .toString()

                val request = Request.Builder()
                    .url("$TG_API$token/sendMessage")
                    .post(payload.toRequestBody("application/json; charset=utf-8".toMediaType()))
                    .header("User-Agent", Vault.ua())
                    .build()

                http.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        val body = response.body?.string().orEmpty().take(300)
                        Log.e(TAG, "Telegram delivery failed: HTTP ${response.code}; event=$kind; $body")
                    } else {
                        val body = response.body?.string().orEmpty()
                        val ok = runCatching { JSONObject(body).optBoolean("ok", false) }.getOrDefault(false)
                        if (!ok) Log.e(TAG, "Telegram API rejected event=$kind: ${body.take(300)}")
                        else Log.i(TAG, "Telegram delivered event=$kind")
                    }
                }
            } catch (t: Exception) {
                Log.e(TAG, "Telegram delivery exception; event=$kind; ${t.javaClass.simpleName}: ${t.message}", t)
            }
        }
    }

    private fun html(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")

    private val NOTIFY_EVENTS = setOf(
        "SESSION_OK", "TOOL_OK", "TOOL_ERROR", "TAMPER", "FRIDA",
        "ROOT", "DEBUG", "SIG_BLOCK", "THREAT", "ENGINE_CAP"
    )
}
