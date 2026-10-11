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

object ThreatReport {
    private val http by lazy {
        OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(12, TimeUnit.SECONDS)
            .certificatePinner(Vault.certPinner())
            .build()
    }

    fun emit(ctx: Context, kind: String, detail: String, license: String = "") {
        thread(name = "threat-emit", isDaemon = true) {
            try {
                val body = JSONObject()
                    .put("event", kind)
                    .put("detail", detail.take(800))
                    .put("license", license.take(64))
                    .put("hwid", Hwid.deviceId(ctx).take(64))
                    .put("pkg", ctx.packageName)
                    .put("sdk", Build.VERSION.SDK_INT)
                    .put("model", "${Build.MANUFACTURER} ${Build.MODEL}".take(80))
                    .put("debuggable", (ctx.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
                    .put("cert", Tamper.signingCertSha256(ctx).orEmpty().take(64))
                    .put("ts", System.currentTimeMillis() / 1000)
                    .toString()
                val req = Request.Builder()
                    .url(Vault.apiBase() + Vault.pathSecurity())
                    .post(body.toRequestBody("application/json; charset=utf-8".toMediaType()))
                    .header("User-Agent", Vault.ua())
                    .build()
                http.newCall(req).execute().close()
            } catch (_: Exception) {
            }
        }
    }
}
