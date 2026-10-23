package com.alvsia.pro.tool

import com.alvsia.pro.sec.SessionGate
import android.content.Context
import java.io.File
import java.io.FileOutputStream

/**
 * Safe reflection-based runner for Chaquopy Python bridge.
 * When Chaquopy is packaged (e.g. in CodeMagic release builds), delegates to
 * alvsia_bridge. When Chaquopy is absent (e.g. in local/test builds),
 * allows clean execution of native fallback without ClassNotFoundException.
 */
object PythonBridgeRunner {
    @Volatile private var startupError: String = "startup not attempted"
    @Volatile private var appContext: Context? = null

    fun startupDiagnostic(): String = startupError

    fun isReady(): Boolean = try {
        val pyClass = Class.forName("com.chaquo.python.Python")
        val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
        isStarted
    } catch (_: Throwable) {
        false
    }

    fun startPlatform(app: android.app.Application) {
        appContext = app.applicationContext
        startupError = "startup in progress"
        try {
            val pyClass = Class.forName("com.chaquo.python.Python")
            val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
            if (!isStarted) {
                val platformClass = Class.forName("com.chaquo.python.android.AndroidPlatform")
                val platformInst = platformClass.getConstructor(android.content.Context::class.java).newInstance(app)
                // Chaquopy's Platform type differs by runtime version. Resolve the
                // actual start(Platform) overload from the instantiated AndroidPlatform
                // instead of loading the non-existent PythonPlatform class.
                val startMethod = pyClass.methods.firstOrNull { method ->
                    method.name == "start" &&
                        java.lang.reflect.Modifier.isStatic(method.modifiers) &&
                        method.parameterTypes.size == 1 &&
                        method.parameterTypes[0].isAssignableFrom(platformInst.javaClass)
                } ?: throw NoSuchMethodException(
                    "Python.start(AndroidPlatform) overload not found"
                )
                startMethod.invoke(null, platformInst)
            }
            startupError = if (isReady()) "Chaquopy ready" else "Python class loaded but runtime reports not started"
        } catch (t: Throwable) {
            val cause = t.cause ?: t
            startupError = "${cause.javaClass.simpleName}: ${cause.message ?: "no detail"}".take(240)
        }
    }

    /** Stage the bundled Unluac jar into the Python engine's configured jars directory.
     * The Python fallback only searches jarsDirPath, whereas Android assets are not
     * filesystem paths. Keep this lazy and scoped to the Lua fallback dependency.
     */
    private fun ensureBundledUnluacJar(jarsDirPath: String): String? {
        return try {
            val context = appContext ?: return null
            val dir = File(jarsDirPath)
            if (!dir.exists() && !dir.mkdirs()) return null
            val candidates = listOf("unluac_2025_12_23.jar", "unluac.jar")
            candidates.map { File(dir, it) }.firstOrNull { it.isFile && it.length() > 1000 }?.let {
                return it.absolutePath
            }
            val dest = File(dir, "unluac_2025_12_23.jar")
            context.assets.open("unluac/unluac_2025_12_23.jar").use { source ->
                FileOutputStream(dest).use { output -> source.copyTo(output) }
            }
            if (dest.isFile && dest.length() > 1000) dest.absolutePath else null
        } catch (_: Throwable) {
            null
        }
    }

    fun runBridge(
        moduleId: Int,
        subId: String,
        inputPath: String,
        extraName: String?,
        workDirPath: String,
        jarsDirPath: String
    ): Pair<Boolean, List<String>> {
        try {
            val pyClass = Class.forName("com.chaquo.python.Python")
            val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
            if (!isStarted) return false to listOf("... Python runtime not ready — native fallback")
            val resolvedJarsDir = jarsDirPath.ifBlank {
                File(appContext?.filesDir ?: File("/data/local/tmp"), "jars").absolutePath
            }
            val stagedUnluacJar = ensureBundledUnluacJar(resolvedJarsDir)

            val py = pyClass.getMethod("getInstance").invoke(null) ?: return false to listOf("... Python instance null")
            val getModule = pyClass.getMethod("getModule", String::class.java)

            val pyObjectCls = Class.forName("com.chaquo.python.PyObject")
            val callAttr = pyObjectCls.getMethod("callAttr", String::class.java, Array<Any?>::class.java)

            val token = SessionGate.sessionToken.trim()
            if (!token.matches(Regex("^[0-9A-Fa-f]{64}$"))) {
                return false to listOf("X AUTH: native session token invalid")
            }

            val bridge = getModule.invoke(py, "alvsia_bridge") ?: return false to listOf("... alvsia_bridge unavailable")
            // Configure the authenticated Python session through a bridge function.
            // This avoids relying on PyObject.get(String), which is not available in
            // some Chaquopy runtimes and caused "PyObject.get" reflection failures.
            // Do not validate the same token twice across Kotlin and Python. The
            // second check used to race with SessionGate.lock() and reject otherwise
            // valid tool launches. configure_runtime performs the authoritative
            // synchronized SessionGate.isTokenCurrent(token) check immediately below.
            val configure = callAttr.invoke(
                bridge,
                "configure_runtime",
                arrayOf<Any?>(token, "1")
            )
            // Chaquopy wraps Python bool True as a PyObject whose toString() == "True".
            // Some Chaquopy runtime versions (especially 3.x under AGP 8.x) may unbox
            // the Python bool to a Java Boolean before returning, so also accept
            // java.lang.Boolean(true).  Case-insensitive match guards against any
            // future runtime that returns the lowercase "true".
            val configureOk = when {
                configure == null -> false
                configure is Boolean -> configure
                else -> configure.toString().trim().equals("True", ignoreCase = true)
            }
            if (!configureOk) {
                val returnedType = configure?.javaClass?.simpleName ?: "null"
                val returnedValue = configure?.toString()?.take(80) ?: "null"
                return false to listOf(
                    "X AUTH DIAG: Kotlin SessionGate accepted token, but Python configure_runtime did not return True",
                    "diagnostic: return_type=$returnedType; return_value=$returnedValue; chaquopy_started=$isStarted; token_shape=64_hex"
                )
            }
            val rawResult = callAttr.invoke(
                bridge,
                "bridge_run_sub",
                arrayOf<Any?>(moduleId, subId, inputPath, extraName ?: "", workDirPath, resolvedJarsDir)
            )
            val log = rawResult?.toString().orEmpty()
            val lines = log.split("\n").filter { it.isNotBlank() }.toMutableList()
            if (stagedUnluacJar != null) lines.add(0, "OK bundled Unluac available: $stagedUnluacJar")
            // Many Python handlers return a structured dict rendered as text rather
            // than a line beginning with "OK". Honor an explicit success result so
            // valid operations aren't reported as failures by the Kotlin wrapper.
            val explicitFalse = log.contains("'ok': False") ||
                    log.contains("\"ok\": false") ||
                    log.contains("\"ok\": False")
            val explicitTrue = log.contains("'ok': True") ||
                    log.contains("\"ok\": true") ||
                    log.contains("\"ok\": True")
            val hasErrorLine = lines.any {
                it.startsWith("X ") || it.startsWith("ERROR:") || it.startsWith("CRITICAL:")
            }
            val hasSuccessLine = lines.any {
                it.startsWith("OK ") || it.startsWith("OUT ") || it.startsWith("> ")
            }
            val bridgeFailed = (explicitFalse && !explicitTrue) || hasErrorLine || (!explicitTrue && !hasSuccessLine)
            return !bridgeFailed to lines
        } catch (e: Throwable) {
            return false to listOf("... bridge error: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    fun setEnv(key: String, value: String) {
        try {
            val pyClass = Class.forName("com.chaquo.python.Python")
            val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
            if (!isStarted) return
            val py = pyClass.getMethod("getInstance").invoke(null) ?: return
            val getModule = pyClass.getMethod("getModule", String::class.java)
            val osMod = getModule.invoke(py, "os") ?: return
            val pyObjectCls = Class.forName("com.chaquo.python.PyObject")
            val callAttr = pyObjectCls.getMethod("callAttr", String::class.java, Array<Any?>::class.java)
            val getObj = pyObjectCls.getMethod("get", Any::class.java)
            val environ = getObj.invoke(osMod, "environ") ?: return
            callAttr.invoke(environ, "__setitem__", arrayOf<Any?>(key, value))
        } catch (_: Throwable) { }
    }

    fun clearEnv(key: String) {
        try {
            val pyClass = Class.forName("com.chaquo.python.Python")
            val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
            if (!isStarted) return
            val py = pyClass.getMethod("getInstance").invoke(null) ?: return
            val getModule = pyClass.getMethod("getModule", String::class.java)
            val osMod = getModule.invoke(py, "os") ?: return
            val pyObjectCls = Class.forName("com.chaquo.python.PyObject")
            val callAttr = pyObjectCls.getMethod("callAttr", String::class.java, Array<Any?>::class.java)
            val getObj = pyObjectCls.getMethod("get", Any::class.java)
            val environ = getObj.invoke(osMod, "environ") ?: return
            callAttr.invoke(environ, "pop", arrayOf<Any?>(key, null))
        } catch (_: Throwable) { }
    }

}
