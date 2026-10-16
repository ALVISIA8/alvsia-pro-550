package com.alvsia.pro.tool

import com.alvsia.pro.sec.SessionGate

/**
 * Safe reflection-based runner for Chaquopy Python bridge.
 * When Chaquopy is packaged (e.g. in CodeMagic release builds), delegates to
 * alvsia_bridge. When Chaquopy is absent (e.g. in local/test builds),
 * allows clean execution of native fallback without ClassNotFoundException.
 */
object PythonBridgeRunner {
    @Volatile private var startupError: String = "startup not attempted"

    fun startupDiagnostic(): String = startupError

    fun isReady(): Boolean = try {
        val pyClass = Class.forName("com.chaquo.python.Python")
        val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
        isStarted
    } catch (_: Throwable) {
        false
    }

    fun startPlatform(app: android.app.Application) {
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
            val configure = callAttr.invoke(
                bridge,
                "configure_runtime",
                arrayOf<Any?>(token, "1")
            )
            if (configure?.toString() != "True") {
                return false to listOf("X AUTH: Python runtime session configuration rejected")
            }
            val rawResult = callAttr.invoke(
                bridge,
                "bridge_run_sub",
                arrayOf<Any?>(moduleId, subId, inputPath, extraName ?: "", workDirPath, jarsDirPath)
            )
            val log = rawResult?.toString().orEmpty()
            val lines = log.split("\n").filter { it.isNotBlank() }
            val bridgeFailed = log.contains("'ok': False") ||
                    lines.any { it.startsWith("X ") || it.startsWith("ERROR:") || it.startsWith("CRITICAL:") } ||
                    lines.none { it.startsWith("OK ") || it.startsWith("OUT ") || it.startsWith("> ") }
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
            val getObj = pyObjectCls.getMethod("get", String::class.java)
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
            val getObj = pyObjectCls.getMethod("get", String::class.java)
            val environ = getObj.invoke(osMod, "environ") ?: return
            callAttr.invoke(environ, "pop", arrayOf<Any?>(key, null))
        } catch (_: Throwable) { }
    }

}
