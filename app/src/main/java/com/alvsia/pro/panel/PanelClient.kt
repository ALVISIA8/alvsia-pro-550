package com.alvsia.pro.panel

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

data class LoginResult(
    val ok: Boolean,
    val message: String,
    val sessionToken: String = "",
    val expiry: String = "",
    val seller: String = "",
    val product: String = "",
)

data class OtpResult(
    val ok: Boolean,
    val message: String,
    val toolTicket: String = "",
)

data class FetchResult(
    val ok: Boolean,
    val message: String,
    val data: ByteArray? = null,
)

/**
 * Solves free-host __test AES cookie (aes.js), then panel API with proto=2 JSON.
 */
class PanelClient {
    companion object {
        const val MAX_ENGINE_BYTES = 12 * 1024 * 1024 // 12MB encrypted core from panel
    }
    private val cookieStore = ConcurrentHashMap<String, MutableList<Cookie>>()

    private val jar = object : CookieJar {
        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            val list = cookieStore.getOrPut(url.host) { mutableListOf() }
            synchronized(list) {
                cookies.forEach { c ->
                    list.removeAll { it.name == c.name }
                    list.add(c)
                }
            }
        }

        override fun loadForRequest(url: HttpUrl): List<Cookie> {
            val list = cookieStore[url.host] ?: return emptyList()
            synchronized(list) {
                return list.filter { it.matches(url) }
            }
        }
    }

    private val clientLoose = OkHttpClient.Builder()
        .cookieJar(jar)
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    /** Prefer pinned TLS; on pin rotate (CDN) fall back once. */
    private val clientPinned = clientLoose.newBuilder()
        .certificatePinner(Vault.certPinner())
        .build()

    private fun client(): OkHttpClient = clientPinned

    var sessionToken: String = ""
        private set
    var lastLicense: String = ""
        private set
    var lastHwid: String = ""
        private set
    var toolTicket: String = ""
        private set

    
    private fun callWithPinFallback(req: Request): okhttp3.Response {
        return try {
            clientPinned.newCall(req).execute()
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            clientLoose.newCall(req).execute()
        } catch (e: java.security.cert.CertificateException) {
            clientLoose.newCall(req).execute()
        }
    }

    private fun base() = Vault.apiBase()

    fun login(license: String, hwid: String): LoginResult {
        lastLicense = license
        lastHwid = hwid
        return try {
            val captchaRaw = openApi(base() + Vault.pathG())
                ?: openApi(base() + Vault.pathCaptcha())
                ?: return LoginResult(false, "Network error")
            if (captchaRaw.trimStart().startsWith("<")) {
                return LoginResult(false, "Gateway still blocked after cookie")
            }
            val r1 = JSONObject(captchaRaw)
            val cid = r1.getString("cid")
            val nonce = r1.getString("nonce")
            val solution = Crypto.solveMechanic(r1.getString("mechanic"))
            val powNonce = Crypto.solvePow(
                r1.optString("pow_prefix", ""),
                r1.optInt("pow_diff", 0)
            )
            val payload = JSONObject()
                .put("license", license)
                .put("game", "PYTHON")
                .put("hwid", hwid)
                .put("solution", solution)
                .put("pow_nonce", powNonce)
                .put("ts", System.currentTimeMillis() / 1000)
            val key = Crypto.transportKey(nonce)
            val pkt = Crypto.b64(
                Crypto.aesCbcEncrypt(key, nonce, payload.toString().toByteArray())
            )
            val loginJson = JSONObject()
                .put("cid", cid)
                .put("packet", pkt)
                .put("proto", 2)
                .toString()
            var raw2 = postJson(base() + Vault.pathS(), loginJson)
            if (raw2.isNullOrBlank() || raw2.trimStart().startsWith("<") || raw2.contains("Update required")) {
                raw2 = postJson(base() + Vault.pathConnect(), loginJson)
            }
            if (raw2.isNullOrBlank()) return LoginResult(false, "Empty login response")
            if (raw2.trimStart().startsWith("<")) return LoginResult(false, "Gateway blocked login")
            val r2 = JSONObject(raw2)
            if (r2.optString("status") == "error") {
                return LoginResult(false, r2.optString("msg", "error"))
            }
            if (r2.optString("status") != "login") {
                return LoginResult(false, "Unexpected: ${r2.optString("status")}")
            }
            val plain = Crypto.aesCbcDecrypt(
                key,
                Crypto.b64d(r2.getString("ip")),
                Crypto.b64d(r2.getString("isp"))
            )
            val data = JSONObject(String(plain))
            if (data.optString("status") != "success") {
                return LoginResult(false, data.optString("msg", "rejected"))
            }
            sessionToken = data.optString("session_token", "")
            LoginResult(
                ok = true,
                message = data.optString("msg", "OK"),
                sessionToken = sessionToken,
                expiry = data.optString("expiry", ""),
                seller = data.optString("seller", ""),
                product = data.optString("product", "PREMIUM"),
            )
        } catch (e: Exception) {
            LoginResult(false, e.message ?: "login failed")
        }
    }

    fun requestOtp(license: String = lastLicense, hwid: String = lastHwid): OtpResult {
        return try {
            ensureGate()
            val json = JSONObject()
                .put("action", "request")
                .put("license", license)
                .put("hwid", hwid)
                .put("session_token", sessionToken)
                .toString()
            val raw = postJson(base() + Vault.pathOtp(), json)
                ?: return OtpResult(false, "OTP request failed")
            if (raw.trimStart().startsWith("<")) return OtpResult(false, "Gateway blocked OTP")
            val j = JSONObject(raw)
            val ok = j.optString("status") == "ok" || j.optBoolean("ok", false)
            OtpResult(ok, j.optString("msg", if (ok) "OTP sent to owner" else "OTP failed"))
        } catch (e: Exception) {
            OtpResult(false, e.message ?: "otp error")
        }
    }

    fun verifyOtp(otp: String, license: String = lastLicense, hwid: String = lastHwid): OtpResult {
        return try {
            ensureGate()
            val json = JSONObject()
                .put("action", "verify")
                .put("license", license)
                .put("hwid", hwid)
                .put("otp", otp)
                .put("session_token", sessionToken)
                .toString()
            val raw = postJson(base() + Vault.pathOtp(), json)
                ?: return OtpResult(false, "OTP verify failed")
            if (raw.trimStart().startsWith("<")) return OtpResult(false, "Gateway blocked OTP")
            val j = JSONObject(raw)
            val ok = j.optString("status") == "ok"
            toolTicket = j.optString("tool_ticket", "")
            OtpResult(ok, j.optString("msg", if (ok) "OTP OK" else "Invalid OTP"), toolTicket)
        } catch (e: Exception) {
            OtpResult(false, e.message ?: "otp verify error")
        }
    }

    fun fetchCore(
        license: String = lastLicense,
        hwid: String = lastHwid,
        ticket: String = toolTicket,
    ): FetchResult {
        return try {
            ensureGate()
            val fetchJson = JSONObject()
                .put("license", license)
                .put("hwid", hwid)
                .put("session_token", sessionToken)
                .put("tool_ticket", ticket)
                .toString()
            var bytes = postJsonBytes(base() + Vault.pathFetch(), fetchJson)
            if (bytes == null) {
                bytes = postBytes(
                    base() + Vault.pathFetch(),
                    mapOf(
                        "license" to license,
                        "hwid" to hwid,
                        "session_token" to sessionToken,
                        "tool_ticket" to ticket,
                    )
                )
            }
            if (bytes == null) return FetchResult(false, "empty fetch")
            if (bytes.size > 16) {
                val n = minOf(32, bytes.size)
                val head = String(bytes, 0, n, Charsets.ISO_8859_1)
                if (head.trimStart().startsWith("<")) {
                    return FetchResult(false, "gateway blocked fetch")
                }
            }
            FetchResult(true, "ok ${bytes.size}b", bytes)
        } catch (e: Exception) {
            FetchResult(false, e.message ?: "fetch error")
        }
    }

    private fun openApi(url: String): String? {
        var body = get(url) ?: return null
        if (body.contains("slowAES") || body.contains("__test")) {
            if (!solveTestCookie(body, url)) return null
            body = get(if (url.contains("?")) "$url&i=1" else "$url?i=1") ?: return null
        }
        return body
    }

    private fun ensureGate() {
        val host = base().toHttpUrlOrNull()?.host ?: return
        val has = cookieStore[host]?.any { it.name == "__test" } == true
        if (!has) openApi(base() + Vault.pathG())
    }

    private fun solveTestCookie(html: String, pageUrl: String): Boolean {
        return try {
            val re = Regex(
                """a=toNumbers\("([0-9a-f]+)"\),b=toNumbers\("([0-9a-f]+)"\),c=toNumbers\("([0-9a-f]+)"\)"""
            )
            val m = re.find(html) ?: return false
            val key = hexToBytes(m.groupValues[1])
            val iv = hexToBytes(m.groupValues[2])
            val ct = hexToBytes(m.groupValues[3])
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val pt = cipher.doFinal(ct)
            val cookieVal = pt.joinToString("") { b -> "%02x".format(b) }
            val httpUrl = pageUrl.toHttpUrlOrNull() ?: return false
            val cookie = Cookie.Builder()
                .name("__test")
                .value(cookieVal)
                .domain(httpUrl.host)
                .path("/")
                .expiresAt(System.currentTimeMillis() + 6L * 3600_000)
                .build()
            jar.saveFromResponse(httpUrl, listOf(cookie))
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val h = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(h.length / 2) { i ->
            h.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun get(url: String): String? {
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", Vault.ua())
            .header("Accept", "application/json, text/html, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .get()
            .build()
        callWithPinFallback(req).use { return it.body?.string() }
    }

    private fun postJson(url: String, json: String): String? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathG())
        val media = "application/json; charset=utf-8".toMediaType()
        val body = json.toRequestBody(media)
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", Vault.ua())
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Content-Type", "application/json")
            .post(body)
            .build()
        callWithPinFallback(req).use { resp ->
            val s = resp.body?.string() ?: return null
            if (s.contains("slowAES") || s.contains("__test")) {
                if (solveTestCookie(s, url)) {
                    callWithPinFallback(req).use { return it.body?.string() }
                }
            }
            return s
        }
    }

    private fun postJsonBytes(url: String, json: String): ByteArray? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathG())
        val media = "application/json; charset=utf-8".toMediaType()
        val body = json.toRequestBody(media)
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", Vault.ua())
            .header("Accept", "*/*")
            .header("Content-Type", "application/json")
            .post(body)
            .build()
        callWithPinFallback(req).use { return it.body?.bytes() }
    }

    private fun postForm(url: String, fields: Map<String, String>): String? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathG())
        val body = FormBody.Builder().apply {
            fields.forEach { (k, v) -> add(k, v) }
        }.build()
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", Vault.ua())
            .header("Accept", "application/json, text/plain, */*")
            .header("Accept-Language", "en-US,en;q=0.9")
            .post(body)
            .build()
        callWithPinFallback(req).use { resp ->
            val s = resp.body?.string() ?: return null
            if (s.contains("slowAES") || s.contains("__test")) {
                if (solveTestCookie(s, url)) {
                    callWithPinFallback(req).use { return it.body?.string() }
                }
            }
            return s
        }
    }

    private fun postBytes(url: String, fields: Map<String, String>): ByteArray? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathG())
        val body = FormBody.Builder().apply {
            fields.forEach { (k, v) -> add(k, v) }
        }.build()
        val req = Request.Builder()
            .url(url)
            .header("User-Agent", Vault.ua())
            .header("Accept", "*/*")
            .post(body)
            .build()
        callWithPinFallback(req).use { return it.body?.bytes() }
    }

    fun securityEvent(jsonBody: String): Boolean {
        return try {
            val media = "application/json; charset=utf-8".toMediaType()
            val body = jsonBody.toRequestBody(media)
            val req = Request.Builder()
                .url(base() + "/security_event.php")
                .post(body)
                .header("User-Agent", Vault.ua())
                .header("Content-Type", "application/json")
                .build()
            callWithPinFallback(req).use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

}
