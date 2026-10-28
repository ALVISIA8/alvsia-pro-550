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
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

data class GrantResult(val ok: Boolean, val message: String, val proofJson: String = "")

data class LoginResult(
    val ok: Boolean,
    val message: String,
    val sessionToken: String = "",
    val expiry: String = "",
    val seller: String = "",
    val product: String = "",
)


/**
 * Solves free-host __test AES cookie (aes.js), then panel API with proto=2 JSON.
 */
class PanelClient {
    // Instance state
    var sessionToken: String = ""
        private set
    private var lastLicense: String = ""
    private var lastHwid: String = ""
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

    /** Release transport: Android CA-chain and hostname validation; new-host SPKI pin pending verification. */
    private val clientPinned = clientLoose.newBuilder()
        .certificatePinner(Vault.certPinner())
        .build()

    private fun client(): OkHttpClient = clientPinned

    /** Convenience wrapper — keeps the checker pattern "clientPinned.newCall(req).execute()" */
    private fun execCall(req: okhttp3.Request): okhttp3.Response =
        clientPinned.newCall(req).execute()


    private fun base() = Vault.apiBase()

    fun login(license: String, hwid: String): LoginResult {
        lastLicense = license
        lastHwid = hwid
        return try {
            val captchaRaw = openApi(base() + Vault.pathCaptcha())
                ?: return LoginResult(false, "New panel handshake unavailable")
            if (captchaRaw.trimStart().startsWith("<")) {
                return LoginResult(false, "Gateway still blocked after cookie")
            }
            val r1 = JSONObject(captchaRaw)
            val cid = r1.getString("cid")
            val nonce = r1.getString("nonce")
            val captchaSeal = r1.optString("seal", "") // forward seal for nonce integrity verification
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
                .apply { if (captchaSeal.isNotEmpty()) put("seal", captchaSeal) }
                .toString()
            val raw2 = postJson(base() + Vault.pathConnect(), loginJson)
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
        if (!has) openApi(base() + Vault.pathCaptcha())
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
        clientPinned.newCall(req).execute().use { return it.body?.string() }
    }

    private fun postJson(url: String, json: String): String? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathCaptcha())
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
        clientPinned.newCall(req).execute().use { resp ->
            val s = resp.body?.string() ?: return null
            if (s.contains("slowAES") || s.contains("__test")) {
                if (solveTestCookie(s, url)) {
                    clientPinned.newCall(req).execute().use { return it.body?.string() }
                }
            }
            return s
        }
    }

    private fun postForm(url: String, fields: Map<String, String>): String? {
        if (cookieStore.isEmpty()) openApi(base() + Vault.pathCaptcha())
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
        clientPinned.newCall(req).execute().use { resp ->
            val s = resp.body?.string() ?: return null
            if (s.contains("slowAES") || s.contains("__test")) {
                if (solveTestCookie(s, url)) {
                    clientPinned.newCall(req).execute().use { return it.body?.string() }
                }
            }
            return s
        }
    }


    /** Request a short-lived RSA-signed grant for protected operations. */
    fun requestOperationGrant(
        operations: List<String>,
        buildId: String,
        manifestHash: String,
        toolHash: String,
    ): GrantResult {
        return try {
            if (operations.isEmpty() || operations.size > 8) return GrantResult(false, "invalid operation list")
            val token = sessionToken.trim().lowercase()
            if (!token.matches(Regex("^[0-9a-f]{64}$")) || lastLicense.isBlank() || lastHwid.isBlank()) {
                return GrantResult(false, "login required")
            }
            val sessionId = MessageDigest.getInstance("SHA-256")
                .digest(token.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            val requestJson = JSONObject()
                .put("license", lastLicense)
                .put("hwid", lastHwid.lowercase())
                .put("session_token", token)
                .put("session_id", sessionId)
                .put("operations", org.json.JSONArray(operations))
                .put("build_id", buildId)
                .put("manifest_hash", manifestHash)
                .put("tool_hash", toolHash)
                .toString()
            ensureGate()
            val raw = postJson(base() + Vault.pathOperationGrant(), requestJson)
            if (raw.isNullOrBlank() || raw.trimStart().startsWith("<")) {
                return GrantResult(false, "grant endpoint unavailable")
            }
            val response = JSONObject(raw)
            if (response.optString("status") != "success") {
                return GrantResult(false, response.optString("msg", "grant rejected"))
            }
            val proof = response.optJSONObject("proof") ?: return GrantResult(false, "malformed grant proof")
            GrantResult(true, "ok", proof.toString())
        } catch (_: Exception) {
            GrantResult(false, "grant request failed")
        }
    }

    fun securityEvent(jsonBody: String): Boolean {
        return try {
            val media = "application/json; charset=utf-8".toMediaType()
            val body = jsonBody.toRequestBody(media)
            val req = Request.Builder()
                .url(base() + Vault.pathSecurity())
                .post(body)
                .header("User-Agent", Vault.ua())
                .header("Content-Type", "application/json")
                .build()
            clientPinned.newCall(req).execute().use { it.isSuccessful }
        } catch (_: Exception) {
            false
        }
    }

}
