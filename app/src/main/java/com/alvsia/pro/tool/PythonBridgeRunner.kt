package com.alvsia.pro.tool

import com.alvsia.pro.sec.SessionGate

/**
 * Safe reflection-based runner for Chaquopy Python bridge.
 * When Chaquopy is packaged (e.g. in CodeMagic release builds), delegates to
 * alvsia_bridge. When Chaquopy is absent (e.g. in local/test builds),
 * allows clean execution of native fallback without ClassNotFoundException.
 */
object PythonBridgeRunner {

    fun isReady(): Boolean = try {
        val pyClass = Class.forName("com.chaquo.python.Python")
        val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
        isStarted
    } catch (_: Throwable) {
        false
    }

    fun startPlatform(app: android.app.Application) {
        try {
            val pyClass = Class.forName("com.chaquo.python.Python")
            val isStarted = pyClass.getMethod("isStarted").invoke(null) as Boolean
            if (!isStarted) {
                val platformClass = Class.forName("com.chaquo.python.android.AndroidPlatform")
                val platformInst = platformClass.getConstructor(android.content.Context::class.java).newInstance(app)
                val platformType = Class.forName("com.chaquo.python.PythonPlatform")
                pyClass.getMethod("start", platformType).invoke(null, platformInst)
            }
        } catch (_: Throwable) {
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

            val osMod = getModule.invoke(py, "os") ?: return false to listOf("... os module unavailable")
            val pyObjectCls = Class.forName("com.chaquo.python.PyObject")
            val getObj = pyObjectCls.getMethod("get", String::class.java)
            val callAttr = pyObjectCls.getMethod("callAttr", String::class.java, Array<Any?>::class.java)

            val environ = getObj.invoke(osMod, "environ") ?: return false to listOf("... environ unavailable")

            val token = SessionGate.sessionToken.trim()
            if (!token.matches(Regex("^[0-9A-Fa-f]{64}$"))) {
                return false to listOf("X AUTH: native session token invalid")
            }

            // Bind verified session into Python environment
            callAttr.invoke(environ, "__setitem__", arrayOf<Any?>("ALVSIA_APK_SESSION", "1"))
            callAttr.invoke(environ, "__setitem__", arrayOf<Any?>("ALVSIA_SESSION_TOKEN", token))
            callAttr.invoke(environ, "__setitem__", arrayOf<Any?>("ALVSIA_SEALED_RUNTIME", "1"))

            val bridge = getModule.invoke(py, "alvsia_bridge") ?: return false to listOf("... alvsia_bridge unavailable")
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
