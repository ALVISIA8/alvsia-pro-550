package com.alvsia.pro.sec

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
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

                // Attach only a cached Android location if the OS has already granted access.
                // Never request permission or enable GPS from this reporting path.
                appendGrantedLocation(ctx, body)

                val req = Request.Builder()
                    .url(Vault.apiBase() + Vault.pathSecurity())
                    .post(body.toString().toRequestBody("application/json; charset=utf-8".toMediaType()))
                    .header("User-Agent", Vault.ua())
                    .build()
                http.newCall(req).execute().close()
            } catch (_: Exception) {
            }
        }
    }

    private fun appendGrantedLocation(ctx: Context, body: JSONObject) {
        val fine = ctx.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val coarse = ctx.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        body.put("location_permission", when {
            fine -> "fine"
            coarse -> "coarse"
            else -> "not_granted"
        })
        if (!fine && !coarse) {
            body.put("location_available", false)
            return
        }

        try {
            val manager = ctx.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            if (manager == null) {
                body.put("location_available", false)
                return
            }
            val locations = manager.getProviders(true).mapNotNull { provider ->
                try {
                    @Suppress("MissingPermission")
                    manager.getLastKnownLocation(provider)
                } catch (_: SecurityException) {
                    null
                } catch (_: IllegalArgumentException) {
                    null
                }
            }
            val best: Location? = locations.maxByOrNull { it.time }
            if (best == null) {
                body.put("location_available", false)
                return
            }
            body.put("location_available", true)
                .put("latitude", best.latitude)
                .put("longitude", best.longitude)
                .put("location_accuracy_m", best.accuracy.toDouble())
                .put("location_time_ms", best.time)
                .put("location_provider", best.provider ?: "unknown")
        } catch (_: SecurityException) {
            body.put("location_available", false)
        } catch (_: Exception) {
            body.put("location_available", false)
        }
    }
}
