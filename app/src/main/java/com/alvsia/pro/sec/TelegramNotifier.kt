package com.alvsia.pro.sec

import android.content.Context
import android.os.Build
import com.alvsia.pro.panel.Hwid
import com.alvsia.pro.panel.Vault
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * TelegramNotifier — modern Telegram Bot API push for ALVISIA PRO.
 * Owner receives formatted MarkdownV2 messages for key events:
 *   - Login (SESSION_OK)
 *   - Threat detected (TAMPER, FRIDA, ROOT, DEBUG, etc.)
 *   - Session errors
 *
 * Config lives in Vault — bot_token and chat_id are XOR-obfuscated
 * the same way API endpoints are. Server-side forwarding is the primary
 * path (ThreatReport → panel → Telegram); this class provides a direct
 * fallback channel when the panel is unreachable.
 */
object TelegramNotifier {

    private val http by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()                     // Telegram CDN — no SPKI pin
    }

    private const val TG_API = "https://api.telegram.org/bot"

    /** Event categories and their emoji */
    private val ICONS = mapOf(
        "SESSION_OK"   to "✅",
        "TAMPER"       to "🚨",
        "FRIDA"        to "🔴",
        "ROOT"         to "⚠️",
        "DEBUG"        to "🔶",
        "SIG_BLOCK"    to "🛑",
        "ENGINE_CAP"   to "🔷",
        "THREAT"       to "🚨",
    )

    /**
     * Send a notification to the owner Telegram bot.
     * Fires in a daemon thread — never blocks the caller.
     *
     * @param ctx     Android context
     * @param kind    Event kind (SESSION_OK, TAMPER, FRIDA, etc.)
     * @param detail  Additional detail string
     * @param license License key (truncated for security)
     */
    fun notify(ctx: Context, kind: String, detail: String = "", license: String = "") {
        // Only notify for significant events
        if (!shouldNotify(kind)) return

        val token = Vault.tgToken()
        val chatId = Vault.tgChatId()
        if (token.isBlank() || chatId.isBlank()) return

        thread(name = "tg-notify", isDaemon = true) {
            try {
                val icon  = ICONS[kind] ?: "ℹ️"
                val hwid  = Hwid.deviceId(ctx).take(16)
                val model = "${Build.MANUFACTURER} ${Build.MODEL}".take(32)
                val sdk   = Build.VERSION.SDK_INT
                val pkg   = ctx.packageName
                val keyMask = if (license.length >= 8)
                    license.take(4) + "****" + license.takeLast(4)
                else "—"
                val ts = java.text.SimpleDateFormat(
                    "dd/MM HH:mm", java.util.Locale.getDefault()
                ).format(java.util.Date())

                val text = buildString {
                    appendLine("$icon *ALVSIA PRO — $kind*")
                    appendLine("`$ts`")
                    appendLine()
                    appendLine("🔑 Key: `$keyMask`")
                    appendLine("📱 Device: `$model` (SDK $sdk)")
                    appendLine("🔐 HWID: `${hwid}…`")
                    if (detail.isNotBlank()) appendLine("📋 Detail: `${detail.take(200)}`")
                    appendLine("📦 Pkg: `$pkg`")
                }
                    // MarkdownV2 escape — only escapes bare brackets/dots
                    .replace(".", "\\.")
                    .replace("!", "\\!")
                    .replace("-", "\\-")
                    .replace("+", "\\+")
                    .replace("=", "\\=")
                    .replace("(", "\\(").replace(")", "\\)")
                    .replace("{", "\\{").replace("}", "\\}")
                    .replace(">", "\\>")
                    .replace("#", "\\#")
                    .replace("|", "\\|")

                val payload = JSONObject()
                    .put("chat_id", chatId)
                    .put("text", text)
                    .put("parse_mode", "MarkdownV2")
                    .put("disable_notification", kind == "SESSION_OK")
                    .toString()

                val req = Request.Builder()
                    .url("$TG_API$token/sendMessage")
                    .post(payload.toRequestBody("application/json".toMediaType()))
                    .header("User-Agent", Vault.ua())
                    .build()

                http.newCall(req).execute().close()
            } catch (_: Exception) {
                // Silently swallow — notification is best-effort only
            }
        }
    }

    private fun shouldNotify(kind: String): Boolean = kind in setOf(
        "SESSION_OK",
        "TAMPER",
        "FRIDA",
        "ROOT",
        "DEBUG",
        "SIG_BLOCK",
        "THREAT",
        "ENGINE_CAP",
    )
}
