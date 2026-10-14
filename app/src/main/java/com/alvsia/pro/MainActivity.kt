package com.alvsia.pro

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.tween
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.lifecycleScope
import com.alvsia.pro.media.PulseAudio
import com.alvsia.pro.panel.Hwid
import com.alvsia.pro.panel.PanelClient
import com.alvsia.pro.sec.Guard
import com.alvsia.pro.sec.RaspEngine
import com.alvsia.pro.sec.SessionGate
import com.alvsia.pro.sec.Tamper
import com.alvsia.pro.sec.ThreatReport
import com.alvsia.pro.tool.CoreBundle
import com.alvsia.pro.tool.CoreSession
import com.alvsia.pro.tool.RamToolVault
import com.alvsia.pro.tool.SubMenus
import com.alvsia.pro.tool.SubTool
import com.alvsia.pro.tool.ToolCatalog
import com.alvsia.pro.tool.ToolEngine
import com.alvsia.pro.ui.home.HomeScreen
import com.alvsia.pro.ui.info.InfoScreen
import com.alvsia.pro.ui.loading.LoadingScreen
import com.alvsia.pro.ui.login.LoginScreen
import com.alvsia.pro.ui.splash.SplashScreen
import com.alvsia.pro.ui.theme.AlvisiaTheme
import com.alvsia.pro.ui.tool.SubMenuScreen
import com.alvsia.pro.ui.tool.ToolWorkspaceScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val panel = PanelClient()
    private val core = CoreSession()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AlvisiaTheme {
                var screen by remember { mutableStateOf("splash") }
                var loading by remember { mutableStateOf(false) }
                var error by remember { mutableStateOf<String?>(null) }
                var info by remember { mutableStateOf("") }
                var product by remember { mutableStateOf("") }
                var expiry by remember { mutableStateOf("") }
                var license by remember { mutableStateOf("") }
                var tools by remember { mutableStateOf(ToolCatalog.defaults()) }
                var loadMsg by remember { mutableStateOf("Decrypting secure core...") }
                var loadProgress by remember { mutableStateOf(0f) }
                var moduleId by remember { mutableStateOf(0) }
                var activeSub by remember { mutableStateOf<SubTool?>(null) }
                var logs by remember { mutableStateOf(listOf<String>()) }
                var running by remember { mutableStateOf(false) }
                val ctx = LocalContext.current
                val hwid = remember { Hwid.deviceId(ctx) }
                val engine = remember {
                    ToolEngine(ctx).also { it.installJarsFromAssets() }
                }

                // Back handler — info screen goes back to home; tool/submenu as before
                BackHandler(enabled = screen != "splash" && screen != "login") {
                    when (screen) {
                        "info" -> { screen = "home" }
                        "tool" -> {
                            activeSub = null
                            logs = emptyList()
                            screen = "submenu"
                        }
                        "submenu" -> {
                            moduleId = 0
                            screen = "home"
                        }
                        else -> { }
                    }
                }

                AnimatedContent(
                    targetState = screen,
                    transitionSpec = {
                        fadeIn(tween(450)) togetherWith fadeOut(tween(350))
                    },
                    label = "screen"
                ) { scr ->
                when (scr) {
                    "splash" -> SplashScreen {
                        try {
                            Guard.checkAndReport(this@MainActivity)
                            RaspEngine.tick(this@MainActivity)
                            val tr = Tamper.evaluate(this@MainActivity)
                            if (!tr.ok) {
                                ThreatReport.emit(
                                    this@MainActivity, "TAMPER", tr.reasons.joinToString("|")
                                )
                            }
                        } catch (_: Exception) { }
                        screen = "login"
                    }
                    "login" -> LoginScreen(
                        hwidFull = hwid,
                        hwidShort = hwid.take(16),
                        loading = loading,
                        error = error,
                        onLogin = login@{ key ->
                            val safeToLogin = try {
                                Guard.checkAndReport(
                                    this@MainActivity,
                                    key,
                                    hardEnforcement = false,
                                )
                            } catch (_: Exception) { false }
                            if (!safeToLogin) {
                                error = "Security check blocked login. Restart the app and try again."
                                return@login
                            }
                            license = key
                            loading = true
                            error = null
                            lifecycleScope.launch {
                                val res = withContext(Dispatchers.IO) { panel.login(key, hwid) }
                                loading = false
                                if (res.ok) {
                                    product = res.product.ifBlank { "PREMIUM" }
                                    expiry = res.expiry
                                    screen = "secure_load"
                                } else {
                                    error = res.message
                                }
                            }
                        }
                    )
                    "secure_load" -> {
                        LaunchedEffect(license) {
                            loading = true
                            error = null
                            val safeAfterLogin = try {
                                Guard.checkAndReport(
                                    this@MainActivity,
                                    license,
                                    hardEnforcement = true,
                                )
                            } catch (_: Exception) { false }
                            if (!safeAfterLogin) {
                                loading = false
                                SessionGate.lock(this@MainActivity)
                                error = "Security check blocked this session. Close debugging or hooking tools and retry."
                                screen = "login"
                                return@LaunchedEffect
                            }

                            loadMsg = "LOADING FOR NOOB | secure session"
                            loadProgress = 0.1f
                            try { Guard.checkAndReport(this@MainActivity, license) } catch (_: Exception) {}

                            // License + panel-issued session token are the only login credentials.
                            // The panel must authorize core fetch directly from this valid session.
                            val fetch = withContext(Dispatchers.IO) {
                                panel.fetchCore(license, hwid)
                            }
                            var engineFromServer = false
                            val data = fetch.data
                            if (fetch.ok && data != null) {
                                val opened = withContext(Dispatchers.Default) {
                                    CoreBundle.open(data)
                                }
                                tools = opened.tools
                                opened.engineBytes?.let { bytes ->
                                    if (bytes.isNotEmpty() && bytes.size <= PanelClient.MAX_ENGINE_BYTES) {
                                        RamToolVault.put("engine", bytes)
                                        engine.installEngineBytes(bytes)
                                        core.loadFromMemory(bytes)
                                        engineFromServer = true
                                    } else {
                                        ThreatReport.emit(
                                            this@MainActivity,
                                            "ENGINE_CAP",
                                            "skip_${bytes.size}",
                                            license
                                        )
                                    }
                                }
                            }
                            if (!engineFromServer) {
                                loading = false
                                SessionGate.lock(this@MainActivity)
                                engine.wipeEngine()
                                core.wipe()
                                error = "Protected engine could not be fetched from the panel. Confirm the panel fetch endpoint accepts a valid session token."
                                screen = "login"
                                return@LaunchedEffect
                            }

                            val tamper = Tamper.evaluate(this@MainActivity)
                            if (!tamper.ok && Tamper.expectedCertSha256.isNotEmpty()) {
                                ThreatReport.emit(
                                    this@MainActivity,
                                    "SIG_BLOCK",
                                    tamper.reasons.joinToString("|"),
                                    license
                                )
                                loading = false
                                SessionGate.lock(this@MainActivity)
                                error = "Integrity check failed"
                                screen = "login"
                                return@LaunchedEffect
                            }

                            val token = panel.sessionToken.trim()
                            if (!token.matches(Regex("^[0-9A-Fa-f]{64}$"))) {
                                loading = false
                                SessionGate.lock(this@MainActivity)
                                error = "Invalid session token from panel"
                                screen = "login"
                                return@LaunchedEffect
                            }
                            val sessionUnlocked = SessionGate.unlock(this@MainActivity, token, license)
                            if (!sessionUnlocked) {
                                loading = false
                                SessionGate.lock(this@MainActivity)
                                error = "Secure session could not be stored. Please login again."
                                screen = "login"
                                return@LaunchedEffect
                            }
                            try { RaspEngine.start(this@MainActivity, license) } catch (_: Exception) {}
                            info = "SYSTEM ONLINE"
                            ThreatReport.emit(this@MainActivity, "SESSION_OK", "license-only unlock", license)
                            loading = false
                            loadMsg = "Opening secure channel..."
                            loadProgress = 0.15f
                            delay(700)
                            loadMsg = "LOADING FOR NOOB | sync workspace"
                            loadProgress = 0.4f
                            delay(900)
                            loadMsg = "Preparing modules..."
                            loadProgress = 0.7f
                            delay(900)
                            loadMsg = "Almost ready..."
                            loadProgress = 0.92f
                            delay(600)
                            try { PulseAudio.start(this@MainActivity, fadeMs = 2000) } catch (_: Exception) {}
                            loadProgress = 1f
                            delay(400)
                            screen = "home"
                        }
                        LoadingScreen(subtitle = loadMsg, progress = loadProgress)
                    }
                    "home" -> HomeScreen(
                        product = product,
                        expiry = expiry,
                        tools = tools,
                        status = info,
                        onTool = { t ->
                            moduleId = t.id
                            activeSub = null
                            logs = emptyList()
                            screen = "submenu"
                        },
                        onInfo = { screen = "info" }   // NEW
                    )
                    // ── NEW: Info screen ─────────────────────────────────────
                    "info" -> InfoScreen(onBack = { screen = "home" })

                    "submenu" -> SubMenuScreen(
                        moduleTitle = SubMenus.title(moduleId),
                        moduleId = moduleId,
                        items = SubMenus.forModule(moduleId),
                        onBack = { screen = "home" },
                        onSelect = { sub ->
                            activeSub = sub
                            logs = emptyList()
                            screen = "tool"
                        }
                    )
                    "tool" -> {
                        val sub = activeSub
                        if (sub == null) {
                            LaunchedEffect(Unit) { screen = "submenu" }
                        } else {
                            ToolWorkspaceScreen(
                                moduleTitle = SubMenus.title(moduleId),
                                moduleId = moduleId,
                                sub = sub,
                                running = running,
                                logs = logs,
                                onBack = {
                                    activeSub = null
                                    logs = emptyList()
                                    screen = "submenu"
                                },
                                onRun = { uri, extra ->
                                    running = true
                                    logs = listOf("> preparing ${sub.id}...")
                                    lifecycleScope.launch {
                                        val result = withContext(Dispatchers.IO) {
                                            engine.runSub(moduleId, sub.id, uri, extra)
                                        }
                                        logs = result
                                        running = false
                                    }
                                }
                            )
                        }
                    }
                }
                } // AnimatedContent
            }
        }
    }

    override fun onDestroy() {
        PulseAudio.stop()
        core.wipe()
        core.wipeCacheDir(this)
        super.onDestroy()
    }
}
