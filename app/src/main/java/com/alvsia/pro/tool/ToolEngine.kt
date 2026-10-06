package com.alvsia.pro.tool


import android.content.Context
import com.alvsia.pro.sec.SessionGate
import com.alvsia.pro.sec.NativeGuard
import com.alvsia.pro.panel.PanelClient
import org.json.JSONObject
import android.net.Uri
import com.chaquo.python.Python
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

class ToolEngine(private val context: Context) {
    private val workDir = File(context.filesDir, "work").also { it.mkdirs() }
    private val engineDir = File(context.filesDir, "orchard").also { it.mkdirs() }
    private val jarsDir = File(context.filesDir, "citrus").also { it.mkdirs() }

    fun outputDir(): File {
        WorkPaths.ensureTree()
        return WorkPaths.alvsiaRoot()
    }

    @Volatile private var ramEngine: ByteArray? = null
    @Volatile private var operationGrant: String = ""
    @Volatile private var operationHwid: String = ""

    fun prepareAuthorization(panel: PanelClient): Boolean {
        return try {
            if (!SessionGate.allowTools(context)) return false
            if (!Python.isStarted()) return false

            // Measurement must happen before operation_grant exists.
            // The sealed loader gets the native build-bound seed and enters
            // measurement-only mode. Normal execution remains grant-gated.
            val py = Python.getInstance()
            val osMod = py.getModule("os")
            val environ = osMod.get("environ") ?: return false

            environ.callAttr(
                "__setitem__",
                "ALVSIA_SEAL_SEED",
                NativeGuard.sealSeedHex()
            )
            environ.callAttr(
                "__setitem__",
                "ALVSIA_MEASUREMENT_ONLY",
                "1"
            )

            val core = try {
                py.getModule("alvsia_core")
            } finally {
                environ.callAttr("pop", "ALVSIA_MEASUREMENT_ONLY", null)
            }

            val m = JSONObject(
                core.callAttr("_alvsia_core_measurement_json").toString()
            )

            val grant = panel.requestOperationGrant(
                buildId = "ALVSIA-20261006-R5.3",
                manifestHash = m.getString("manifest_hash"),
                toolHash = m.getString("tool_hash")
            ) ?: return false

            operationGrant = grant
            operationHwid = panel.lastHwid
            true
        } catch (_: Exception) {
            operationGrant = ""
            operationHwid = ""
            false
        }
    }

    fun installEngineBytes(engine: ByteArray?) {
        if (engine == null || engine.isEmpty()) return
        ramEngine?.fill(0)
        ramEngine = engine.copyOf()
        // purge any legacy on-disk engine from older builds
        try {
            File(engineDir, "mango_kernel.py").delete()
            File(engineDir, "__init__.py").delete()
        } catch (_: Exception) {
        }
    }

    fun wipeEngine() {
        ramEngine?.fill(0)
        ramEngine = null
    }

    fun hasRamEngine(): Boolean = ramEngine != null && ramEngine!!.isNotEmpty()

    /**
     * R5.3: plaintext JAR extraction from APK assets is disabled.
     *
     * The sealed runtime is the only supported execution path.
     * No JAR is copied from assets/unluac into app storage.
     */
    fun installJarsFromAssets() {
        return
    }

    private fun copyUri(uri: Uri, dest: File): Boolean {
        return try {
            context.contentResolver.openInputStream(uri)?.use { ins ->
                FileOutputStream(dest).use { outs -> ins.copyTo(outs) }
            }
            dest.exists() && dest.length() > 0
        } catch (_: Exception) {
            false
        }
    }

    private fun stageInput(uri: Uri?, moduleId: Int): Pair<String, List<String>> {
        val notes = mutableListOf<String>()
        if (uri == null) return "" to notes
        val nameHint = uri.lastPathSegment?.substringAfterLast('/') ?: "input.bin"
        val safe = nameHint.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "input.bin" }
        val staged = File(WorkPaths.moduleWork(moduleId), "in_${System.currentTimeMillis()}_$safe")
        if (!copyUri(uri, staged)) {
            notes.add("X Failed to read selected file")
            return "" to notes
        }
        // also copy snapshot under IN/
        try {
            val snap = File(WorkPaths.moduleIn(moduleId), safe)
            staged.copyTo(snap, overwrite = true)
            notes.add("OK INPUT staged -> ${snap.absolutePath}")
        } catch (_: Exception) {
            notes.add("OK INPUT staged (work only) -> ${staged.absolutePath}")
        }
        notes.add("size ${staged.length()} bytes")
        return staged.absolutePath to notes
    }

    fun run(toolId: Int, inputUri: Uri?, extraName: String?): List<String> {
        try {
            SessionGate.allowTools(context)
        } catch (e: SecurityException) {
            val reason = e.message?.removePrefix("BLOCKED:") ?: "gate_fail"
            return listOf("X Session blocked: $reason — re-login required")
        }
        return runSub(toolId, "mod_$toolId", inputUri, extraName)
    }

    fun runSub(moduleId: Int, subId: String, inputUri: Uri?, extraName: String?): List<String> {
        try {
            SessionGate.allowTools(context)
        } catch (e: SecurityException) {
            val reason = e.message?.removePrefix("BLOCKED:") ?: "gate_fail"
            return listOf("X Session blocked: $reason — re-login required")
        }
        WorkPaths.bindApp(context)
        WorkPaths.readme(context)
        WorkPaths.ensureTree()
        installJarsFromAssets()

        val lines = mutableListOf<String>()
        lines.add("> ${SubMenus.title(moduleId)} | $subId")
        lines.add("PIPELINE IN -> WORK -> OUT")

        val (inputPath, stageNotes) = stageInput(inputUri, moduleId)
        lines.addAll(stageNotes)

        // Bridge first for all modules; native fallback below

        if (inputPath.isEmpty() && needsInput(moduleId, subId)) {
            lines.add("X No input file ? use SELECT FILE")
            lines.add("hint: output folder ${WorkPaths.moduleOut(moduleId).absolutePath}")
            return lines
        }

        try {
            File(context.filesDir, "sub_cmd.txt").writeText(subId)
        } catch (_: Exception) {
        }

        // LUA decompile on ART (no external Java)
        if (subId == "lua_decompile" || subId.contains("unluac")) {
            if (inputPath.isNotEmpty()) {
                val inFile = File(inputPath)
                val outFile = File(WorkPaths.moduleOut(moduleId), inFile.nameWithoutExtension + "_decompiled.lua")
                lines.addAll(UnluacRunner.decompile(inFile, outFile))
                if (outFile.isFile && outFile.length() > 0) {
                    lines.add("OK OUT -> ${WorkPaths.moduleOut(moduleId).absolutePath}")
                    return lines
                }
                lines.add("... ART unluac failed, trying Python bridge")
            }
        }

        // Bridge for heavier modules
        try {
            if (Python.isStarted()) {
                val py = Python.getInstance()
                // Bind session into Python process only if gate passed
                try {
                    val osMod = py.getModule("os")
                    val environ = osMod.get("environ")
                    if (environ != null) {
                        if (SessionGate.sessionOk && operationGrant.isNotBlank()) {
                            environ.callAttr("__setitem__", "ALVSIA_SESSION_TOKEN", SessionGate.sessionToken)
                            environ.callAttr("__setitem__", "ALVSIA_DEVICE_ID", operationHwid)
                            environ.callAttr("__setitem__", "ALVSIA_OPERATION_GRANT", operationGrant)
                        } else {
                            environ.callAttr("pop", "ALVSIA_SESSION_TOKEN", null)
                            environ.callAttr("pop", "ALVSIA_DEVICE_ID", null)
                            environ.callAttr("pop", "ALVSIA_OPERATION_GRANT", null)
                        }
                    }
                } catch (_: Exception) {
                }
                // The protected Python modules are sealed at rest. The native build-bound
                // seed is injected only after the server grant has been accepted.
                try {
                    val osMod2 = py.getModule("os")
                    val env2 = osMod2.get("environ")
                    env2?.callAttr("__setitem__", "ALVSIA_SEAL_SEED", NativeGuard.sealSeedHex())
                } catch (_: Exception) {
                    lines.add("X sealed runtime unavailable")
                    return lines
                }
                val bridge = py.getModule("alvsia_bridge")
                val log = bridge.callAttr(
                    "run_tool",
                    moduleId,
                    subId,
                    inputPath,
                    WorkPaths.alvsiaRoot().absolutePath,
                    engineDir.absolutePath,
                    jarsDir.absolutePath
                ).toString()
                lines.addAll(log.split("\n").filter { it.isNotBlank() })
                mirrorMsvToOut(moduleId, lines)
                // Never report a successful output when the Python engine explicitly
                // returned a failed operation. This was causing the UI to show
                // "OK OUT" even when decompilation had failed.
                val bridgeFailed = log.contains("'ok': False") ||
                    log.contains("\"ok\": false", ignoreCase = true) ||
                    log.contains("X AUTH:") ||
                    log.contains("X input missing")
                if (bridgeFailed) {
                    lines.add("X OUT -> operation failed; see engine diagnostics above")
                } else {
                    lines.add("OK OUT -> ${WorkPaths.moduleOut(moduleId).absolutePath}")
                }
                return lines
            } else {
                lines.add("... Python runtime not ready ? native fallback")
            }
        } catch (e: Exception) {
            lines.add("... bridge: ${e.message ?: e.javaClass.simpleName}")
            lines.add("... native fallback")
        }

        when (moduleId) {
            11 -> return lines + runHash(subId, inputPath)
            3 -> return lines + runObb(subId, inputPath)
            8 -> return lines + runStrings(subId, inputPath)
            4 -> return lines + runObbRepack(subId, inputPath)
        }

        return lines + nativeFallback(moduleId, subId, inputPath, extraName)
    }

    private fun needsInput(moduleId: Int, subId: String): Boolean {
        if (subId.contains("session") || subId.contains("local") || subId.contains("report") || subId.contains("clear")) return false
        return moduleId !in listOf(7, 13, 15) && !subId.contains("clear")
    }

    private fun mirrorMsvToOut(moduleId: Int, lines: MutableList<String>) {
        try {
            val msv = File(context.filesDir, "MSV_WORK")
            if (!msv.exists()) return
            val dest = WorkPaths.moduleOut(moduleId)
            msv.walkTopDown().maxDepth(4).forEach { f ->
                if (f.isFile && f.length() > 0 && f.length() < 80_000_000) {
                    val rel = f.relativeTo(msv).path
                    val out = File(dest, rel)
                    out.parentFile?.mkdirs()
                    try {
                        f.copyTo(out, overwrite = true)
                    } catch (_: Exception) {
                    }
                }
            }
            lines.add("OK mirrored MSV_WORK -> ${dest.absolutePath}")
        } catch (e: Exception) {
            lines.add("... mirror skip: ${e.message}")
        }
    }

    // ?? Phase 2 proof: HASH ??
    private fun runHash(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) {
            lines.add("X Select a file first")
            return lines
        }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(11)
        try {
            val md5 = digest(f, "MD5")
            val sha1 = digest(f, "SHA-1")
            val sha256 = digest(f, "SHA-256")
            when (subId) {
                "hash_sha256" -> {
                    lines.add("SHA-256  $sha256")
                    val out = File(outDir, "sha256_${f.name}.txt")
                    out.writeText("file=${f.name}\nsize=${f.length()}\nSHA-256=$sha256\n")
                    lines.add("OK OUTPUT -> ${out.absolutePath}")
                }
                "hash_map" -> {
                    val parent = f.parentFile
                    val report = File(outDir, "hashmap_${System.currentTimeMillis()}.txt")
                    val sb = StringBuilder()
                    sb.appendLine("# hash map")
                    var n = 0
                    parent?.listFiles()?.filter { it.isFile }?.take(200)?.forEach { file ->
                        val h = digest(file, "SHA-256")
                        sb.appendLine("${file.name}\t${file.length()}\t$h")
                        n++
                    }
                    report.writeText(sb.toString())
                    lines.add("OK hashed $n files")
                    lines.add("OK OUTPUT -> ${report.absolutePath}")
                }
                else -> {
                    lines.add("MD5     $md5")
                    lines.add("SHA-1   $sha1")
                    lines.add("SHA-256 $sha256")
                    lines.add("size    ${f.length()} bytes")
                    val out = File(outDir, "hash_${f.name}.txt")
                    out.writeText(
                        "file=${f.name}\nsize=${f.length()}\nMD5=$md5\nSHA-1=$sha1\nSHA-256=$sha256\n"
                    )
                    lines.add("OK OUTPUT -> ${out.absolutePath}")
                }
            }
        } catch (e: Exception) {
            lines.add("X ${e.message ?: "hash failed"}")
        }
        return lines
    }

    private fun digest(f: File, algo: String): String {
        val md = MessageDigest.getInstance(algo)
        FileInputStream(f).use { ins ->
            val buf = ByteArray(8192)
            while (true) {
                val n = ins.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    // ?? Phase 2 proof: OBB / ZIP ??
    private fun runObb(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) {
            lines.add("X Select an .obb / .zip file first")
            return lines
        }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(3)
        when (subId) {
            "obb_info" -> {
                lines.addAll(zipInfo(f, outDir))
            }
            "obb_antireset" -> {
                lines.addAll(zipExtract(f, File(outDir, "antireset_${stripExt(f.name)}")))
                lines.add("hint: anti-reset helpers extracted if zip-based OBB")
            }
            else -> {
                // obb_unzip default
                lines.addAll(zipExtract(f, File(outDir, "unpack_${stripExt(f.name)}")))
            }
        }
        return lines
    }

    private fun runObbRepack(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) {
            lines.add("X Select source file / folder marker")
            return lines
        }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(4)
        try {
            // If input is zip/obb, re-copy as staged repack baseline
            val dest = File(outDir, "repack_${f.name}")
            f.copyTo(dest, overwrite = true)
            lines.add("OK staged repack baseline -> ${dest.absolutePath}")
            lines.add("hint: edit unpacked tree under OUT/OBB then re-run with tools as needed")
        } catch (e: Exception) {
            lines.add("X ${e.message}")
        }
        return lines
    }

    private fun zipInfo(f: File, outDir: File): List<String> {
        val lines = mutableListOf<String>()
        try {
            ZipFile(f).use { zf ->
                var files = 0
                var dirs = 0
                var total = 0L
                val en = zf.entries()
                val index = StringBuilder()
                index.appendLine("# ${f.name} size=${f.length()}")
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    if (e.isDirectory) dirs++ else {
                        files++
                        total += e.size
                    }
                    index.appendLine("${e.name}\t${e.size}")
                }
                lines.add("entries file=$files dir=$dirs")
                lines.add("uncompressed ~$total bytes")
                val rep = File(outDir, "info_${f.name}.txt")
                rep.writeText(index.toString())
                lines.add("OK OUTPUT -> ${rep.absolutePath}")
            }
        } catch (e: Exception) {
            lines.add("X not a zip/obb or corrupt: ${e.message}")
            lines.add("size ${f.length()} ? raw file kept under IN/")
        }
        return lines
    }

    private fun zipExtract(f: File, dest: File): List<String> {
        val lines = mutableListOf<String>()
        dest.mkdirs()
        var count = 0
        try {
            ZipFile(f).use { zf ->
                val en = zf.entries()
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    val out = File(dest, e.name)
                    if (e.isDirectory) {
                        out.mkdirs()
                    } else {
                        out.parentFile?.mkdirs()
                        zf.getInputStream(e).use { ins ->
                            FileOutputStream(out).use { outs -> ins.copyTo(outs) }
                        }
                        count++
                    }
                }
            }
            lines.add("OK extracted $count files")
            lines.add("OK OUTPUT -> ${dest.absolutePath}")
        } catch (e: Exception) {
            // try ZipInputStream fallback
            try {
                count = 0
                ZipInputStream(BufferedInputStream(FileInputStream(f))).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val out = File(dest, entry.name)
                        if (entry.isDirectory) out.mkdirs()
                        else {
                            out.parentFile?.mkdirs()
                            FileOutputStream(out).use { outs -> zis.copyTo(outs) }
                            count++
                        }
                        zis.closeEntry()
                        entry = zis.nextEntry
                    }
                }
                lines.add("OK extracted $count files (stream)")
                lines.add("OK OUTPUT -> ${dest.absolutePath}")
            } catch (e2: Exception) {
                lines.add("X extract failed: ${e.message}")
                lines.add("... ${e2.message}")
            }
        }
        return lines
    }

    // ?? Phase 2 proof: STRINGS ??
    private fun runStrings(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) {
            lines.add("X Select a binary / package file first")
            return lines
        }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(8)
        val minLen = if (subId == "str_filter") 4 else 4
        try {
            val found = extractAsciiStrings(f, minLen)
            lines.add("OK strings found: ${found.size} (minLen=$minLen)")
            val out = File(outDir, "strings_${stripExt(f.name)}.txt")
            out.writeText(found.joinToString("\n"))
            lines.add("OK OUTPUT -> ${out.absolutePath}")
            found.take(12).forEach { lines.add("  | ${it.take(80)}") }
            if (found.size > 12) lines.add("  ... ${found.size - 12} more in file")
        } catch (e: Exception) {
            lines.add("X ${e.message}")
        }
        return lines
    }

    private fun extractAsciiStrings(f: File, minLen: Int): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        FileInputStream(f).use { ins ->
            val buf = ByteArray(8192)
            while (true) {
                val n = ins.read(buf)
                if (n <= 0) break
                for (i in 0 until n) {
                    val c = buf[i].toInt() and 0xFF
                    if (c in 32..126) {
                        cur.append(c.toChar())
                    } else {
                        if (cur.length >= minLen) out.add(cur.toString())
                        cur.setLength(0)
                    }
                }
            }
        }
        if (cur.length >= minLen) out.add(cur.toString())
        return out.distinct()
    }

    private fun stripExt(name: String): String {
        val i = name.lastIndexOf('.')
        return if (i > 0) name.substring(0, i) else name
    }

    private fun nativeFallback(
        moduleId: Int,
        subId: String,
        inputPath: String,
        extraName: String?
    ): List<String> {
        val lines = mutableListOf<String>()
        when (moduleId) {
            11 -> return runHash(subId, inputPath)
            3 -> return runObb(subId, inputPath)
            8 -> return runStrings(subId, inputPath)
            1, 7 -> {
                if (inputPath.isEmpty()) {
                    lines.add("X No input")
                    return lines
                }
                lines.addAll(zipExtract(File(inputPath), File(WorkPaths.moduleOut(moduleId), "extract")))
            }
            10 -> {
                if (inputPath.isEmpty()) {
                    lines.add("X No input")
                    return lines
                }
                val f = File(inputPath)
                val newName = extraName?.ifBlank { null } ?: "renamed_${f.name}"
                val dest = File(WorkPaths.moduleOut(10), newName)
                f.copyTo(dest, overwrite = true)
                lines.add("OK OUTPUT -> ${dest.absolutePath}")
            }
            13 -> {
                lines.add("session markers OK")
                lines.add("OUT -> ${WorkPaths.moduleOut(13).absolutePath}")
            }
            15 -> {
                val rep = File(WorkPaths.moduleOut(15), "session_report.txt")
                val root = WorkPaths.alvsiaRoot()
                val sb = StringBuilder()
                sb.appendLine("ALVSIA session report")
                root.walkTopDown().maxDepth(3).forEach { p ->
                    if (p.isDirectory) sb.appendLine("DIR ${p.relativeTo(root)}")
                }
                rep.writeText(sb.toString())
                lines.add("OK OUTPUT -> ${rep.absolutePath}")
            }
            else -> {
                lines.add("X Module $moduleId native path limited in this build")
                lines.add("hint: use Hash (11), OBB (03), Strings (08) as verified pipelines")
                lines.add("OUT folder -> ${WorkPaths.moduleOut(moduleId).absolutePath}")
                if (inputPath.isNotEmpty()) {
                    val f = File(inputPath)
                    val copy = File(WorkPaths.moduleOut(moduleId), "copy_${f.name}")
                    try {
                        f.copyTo(copy, overwrite = true)
                        lines.add("OK file copied -> ${copy.absolutePath}")
                    } catch (_: Exception) {
                    }
                }
            }
        }
        return lines
    }
}
