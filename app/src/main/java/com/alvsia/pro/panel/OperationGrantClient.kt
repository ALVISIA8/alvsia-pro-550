package com.alvsia.pro.panel

import android.content.Context
import com.alvsia.pro.sec.SessionGate
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Requests a short-lived signed grant from the pinned panel API.
 * The RSA private key stays server-side; this class never logs credentials or grant contents.
 */
object OperationGrantClient {
    const val BUILD_ID = "ALVSIA-20260923-V46"

    data class Result(
        val ok: Boolean,
        val grantJson: String = "",
        val message: String = ""
    )

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .certificatePinner(Vault.certPinner())
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .callTimeout(25, TimeUnit.SECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
    }

    fun request(context: Context, operationId: String): Result {
        val license = SessionGate.currentLicense().trim()
        val token = SessionGate.sessionToken.trim()
        val hwid = Hwid.deviceId(context).trim().lowercase()
        if (license.isBlank() || !token.matches(Regex("^[0-9A-Fa-f]{64}$")) ||
            !hwid.matches(Regex("^[0-9a-f]{64}$"))) {
            return Result(false, message = "authenticated license/device/session unavailable")
        }

        return try {
            val payload = JSONObject()
                .put("license", license)
                .put("hwid", hwid)
                .put("session_token", token)
                .put("operation_id", operationId)
                .put("build_id", BUILD_ID)
                .toString()
            val body = payload.toRequestBody("application/json; charset=utf-8".toMediaType())
            val request = Request.Builder()
                .url(Vault.apiBase().trimEnd('/') + "/operation_grant.php")
                .header("Accept", "application/json")
                .header("Cache-Control", "no-store")
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body?.string().orEmpty()
                val root = try { JSONObject(raw) } catch (_: Exception) {
                    return Result(false, message = "grant endpoint returned invalid JSON (HTTP ${response.code})")
                }
                if (!response.isSuccessful || !root.optBoolean("ok", false)) {
                    val reason = root.optString("error", "grant request rejected")
                        .replace(Regex("[^A-Za-z0-9 _.:/-]"), "")
                        .take(140)
                    return Result(false, message = "grant request failed (HTTP ${response.code}): $reason")
                }
                val grant = root.optJSONObject("grant")
                    ?: return Result(false, message = "grant response missing signed payload")
                Result(true, grant.toString(), "signed grant received")
            }
        } catch (e: Exception) {
            Result(false, message = "grant network error: ${e.javaClass.simpleName}")
        }
    }
}
