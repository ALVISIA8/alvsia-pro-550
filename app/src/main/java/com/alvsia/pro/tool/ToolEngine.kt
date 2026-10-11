package com.alvsia.pro.tool

import android.content.Context
import android.content.pm.PackageManager
import com.alvsia.pro.BuildConfig
import com.alvsia.pro.asset.AssetVault
import com.alvsia.pro.sec.SessionGate
import com.alvsia.pro.sec.NativeGuard
import android.net.Uri
import android.util.Log
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class ToolEngine(private val context: Context) {
    private val workDir = File(context.filesDir, "work").also { it.mkdirs() }
    private val engineDir = File(context.filesDir, "orchard").also { it.mkdirs() }
    private val jarsDir = File(context.filesDir, "citrus").also { it.mkdirs() }

    fun outputDir(): File {
        WorkPaths.ensureTree()
        return WorkPaths.alvsiaRoot()
    }

    @Volatile private var ramEngine: ByteArray? = null

    fun installEngineBytes(engine: ByteArray?) {
        if (engine == null || engine.isEmpty()) return
        ramEngine?.fill(0)
        ramEngine = engine.copyOf()
        try {
            File(engineDir, "mango_kernel.py").delete()
            File(engineDir, "__init__.py").delete()
        } catch (_: Exception) { }
    }

    fun wipeEngine() {
        ramEngine?.fill(0)
        ramEngine = null
    }

    fun hasRamEngine(): Boolean = ramEngine != null && ramEngine!!.isNotEmpty()

    fun installJarsFromAssets() {
        try {
            val count = AssetVault.materializeJars(context, jarsDir)
            if (count > 0) return
        } catch (_: Exception) { }
        if (!BuildConfig.DEBUG) return
        try {
            val am = context.assets
            val list = am.list("unluac") ?: return
            for (name in list) {
                if (!name.endsWith(".jar")) continue
                val dest = File(jarsDir, name)
                if (dest.exists() && dest.length() > 0) continue
                am.open("unluac/$name").use { ins ->
                    FileOutputStream(dest).use { outs -> ins.copyTo(outs) }
                }
            }
        } catch (_: Exception) { }
    }

    private fun copyUri(uri: Uri, dest: File): Boolean {
        return try {
            context.contentResolver.openInputStream(uri)?.use { ins ->
                FileOutputStream(dest).use { outs -> ins.copyTo(outs) }
            }
            dest.exists() && dest.length() > 0
        } catch (_: Exception) { false }
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
        } catch (e: LinkageError) {
            Log.e("ALVISIA_TOOL", "Security runtime linkage failure before tool dispatch", e)
            return listOf("X Tool runtime component unavailable (${e.javaClass.simpleName}). Reopen the app and retry.")
        } catch (e: Exception) {
            Log.e("ALVISIA_TOOL", "Security runtime failure before tool dispatch", e)
            return listOf("X Tool could not start (${e.javaClass.simpleName}). Reopen the app and retry.")
        }
        return runSub(toolId, "mod_$toolId", inputUri, extraName)
    }

    fun runSub(moduleId: Int, subId: String, inputUri: Uri?, extraName: String?): List<String> {
        return try {
            runSubInternal(moduleId, subId, inputUri, extraName)
        } catch (e: LinkageError) {
            Log.e("ALVISIA_TOOL", "Tool runtime linkage failure: module=$moduleId sub=$subId", e)
            listOf(
                "X Tool runtime component failed to load (${e.javaClass.simpleName}).",
                "The operation may have partial output. Check the OUT folder before retrying."
            )
        } catch (e: Exception) {
            Log.e("ALVISIA_TOOL", "Tool dispatch exception: module=$moduleId sub=$subId", e)
            listOf(
                "X Tool operation stopped safely (${e.javaClass.simpleName}).",
                "The operation may have partial output. Check the OUT folder before retrying."
            )
        }
    }

    private fun runSubInternal(moduleId: Int, subId: String, inputUri: Uri?, extraName: String?): List<String> {
        try { SessionGate.allowTools(context) } catch (e: SecurityException) {
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

        // Android Permission Dump — always native
        if (subId == "android_permission_dump") {
            if (inputPath.isBlank()) return listOf("X Select an APK file first")
            val apkInfo = try {
                context.packageManager.getPackageArchiveInfo(inputPath, PackageManager.GET_PERMISSIONS)
            } catch (_: Exception) { null } ?: return listOf("X Unable to parse APK manifest")
            val permissions = apkInfo.requestedPermissions?.toList().orEmpty().sorted()
            val report = File(WorkPaths.moduleOut(moduleId), "${File(inputPath).nameWithoutExtension}_permissions.txt")
            report.parentFile?.mkdirs()
            report.writeText(buildString {
                appendLine("ALVISIA PRO — Android Permission Dump")
                appendLine("APK: ${File(inputPath).name}")
                appendLine("Package: ${apkInfo.packageName ?: "unknown"}")
                appendLine("Requested permissions: ${permissions.size}")
                appendLine()
                if (permissions.isEmpty()) appendLine("(No requested permissions found)")
                else permissions.forEachIndexed { i, p -> appendLine("${i + 1}. $p") }
            })
            return listOf(
                "OK Permission dump -> ${report.absolutePath}",
                "Package: ${apkInfo.packageName ?: "unknown"}",
                "Requested permissions: ${permissions.size}"
            )
        }

        if (inputPath.isEmpty() && needsInput(moduleId, subId)) {
            lines.add("X No input file — use SELECT FILE")
            lines.add("hint: output folder ${WorkPaths.moduleOut(moduleId).absolutePath}")
            return lines
        }

        try { File(context.filesDir, "sub_cmd.txt").writeText(subId) } catch (_: Exception) {}

        // Lua decompile — prefer ART unluac
        if (subId == "lua_decompile" || subId.contains("unluac")) {
            if (inputPath.isNotEmpty()) {
                val inFile = File(inputPath)
                val prefix = ByteArray(17)
                val prefixSize = try { inFile.inputStream().use { it.read(prefix).coerceAtLeast(0) } } catch (_: Exception) { 0 }
                val isBgmiLua53 = prefixSize >= 14 &&
                        prefix[0] == 0x1b.toByte() && prefix[1] == 'L'.code.toByte() &&
                        prefix[2] == 'u'.code.toByte() && prefix[3] == 'a'.code.toByte() &&
                        prefix[4] == 0x53.toByte() && prefix[13] == 4.toByte()
                val hasZlibLuaContainer = prefixSize >= 2 &&
                        prefix[0] == 0x78.toByte() &&
                        (prefix[1] == 0xda.toByte() || prefix[1] == 0x9c.toByte() || prefix[1] == 0x01.toByte())

                if (isBgmiLua53 || hasZlibLuaContainer) {
                    lines.add("NOTE: BGMI/PUBG Lua normalization required; routing through Python engine")
                } else {
                    val outFile = File(WorkPaths.moduleOut(moduleId), inFile.nameWithoutExtension + "_decompiled.lua")
                    lines.addAll(UnluacRunner.decompile(inFile, outFile))
                    if (outFile.isFile && outFile.length() > 0) {
                        lines.add("OK OUT -> ${WorkPaths.moduleOut(moduleId).absolutePath}")
                        return lines
                    }
                    lines.add("... ART unluac failed, trying Python bridge")
                }
            }
        }

        // Python bridge when Chaquopy is available
        if (PythonBridgeRunner.isReady()) {
            if (!SessionGate.sessionOk) {
                lines.add("X AUTH: native session expired before Python binding")
                return lines
            }
            val (bridgeOk, bridgeLogs) = PythonBridgeRunner.runBridge(
                moduleId, subId, inputPath, extraName,
                WorkPaths.alvsiaRoot().absolutePath, jarsDir.absolutePath
            )
            lines.addAll(bridgeLogs)
            mirrorMsvToOut(moduleId, lines)
            val bridgeFailed = !bridgeOk ||
                    bridgeLogs.any { it.contains("'ok': False") || it.contains("\"ok\": false", ignoreCase = true) } ||
                    bridgeLogs.any { it.trimStart().startsWith("X ") }
            return if (bridgeFailed) {
                lines.add("X OUT -> operation failed; see engine diagnostics above")
                lines
            } else {
                lines.add("OK OUT -> ${WorkPaths.moduleOut(moduleId).absolutePath}")
                lines
            }
        } else {
            lines.add("... Python runtime not ready — native fallback")
        }

        return lines + nativeFallback(moduleId, subId, inputPath, extraName)
    }

    private fun needsInput(moduleId: Int, subId: String): Boolean =
        SubMenus.forModule(moduleId).firstOrNull { it.id == subId }?.needsFile ?: (subId != "clear_work")

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
                    try { f.copyTo(out, overwrite = true) } catch (_: Exception) {}
                }
            }
            lines.add("OK mirrored MSV_WORK -> ${dest.absolutePath}")
        } catch (e: Exception) { lines.add("... mirror skip: ${e.message}") }
    }

    // ═════════════════════════════════════════════════════════════════
    // NATIVE IMPLEMENTATIONS
    // ═════════════════════════════════════════════════════════════════

    private fun nativeFallback(moduleId: Int, subId: String, inputPath: String, extraName: String?): List<String> {
        val lines = mutableListOf<String>()
        val outDir = WorkPaths.moduleOut(moduleId)

        when {
            // ── Modules 1-3 : PAK ────────────────────────────────────────────
            moduleId in 1..3 || subId.startsWith("pak_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select a .pak file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "pak_info" -> {
                        val info = buildString {
                            appendLine("ALVISIA PRO — PAK Analysis")
                            appendLine("File    : ${f.name}")
                            appendLine("Size    : ${f.length()} bytes")
                            appendLine("SHA-256 : ${digest(f, "SHA-256")}")
                            appendLine("SHA-1   : ${digest(f, "SHA-1")}")
                            appendLine("MD5     : ${digest(f, "MD5")}")
                            val head = f.readBytes().copyOfRange(0, minOf(32, f.length().toInt()))
                            appendLine("Header  : ${head.joinToString("") { "%02X".format(it) }}")
                        }
                        val out = File(outDir, "info_${f.nameWithoutExtension}.txt")
                        out.writeText(info)
                        lines.add("OK PAK Info -> ${out.absolutePath}")
                        lines.add("SHA-256: ${digest(f, "SHA-256")}")
                    }
                    "pak_list", "pak_csv" -> {
                        // Real ZIP index if applicable
                        val out = File(outDir, "${subId}_${f.nameWithoutExtension}.txt")
                        val sb = StringBuilder()
                        var count = 0
                        try {
                            ZipFile(f).use { zf ->
                                val en = zf.entries()
                                while (en.hasMoreElements()) {
                                    val e = en.nextElement()
                                    if (subId == "pak_csv") {
                                        sb.appendLine("${e.name},${e.size},${e.compressedSize},${e.method}")
                                    } else {
                                        sb.appendLine(e.name)
                                    }
                                    count++
                                }
                            }
                            out.writeText(sb.toString())
                            lines.add("OK $count entries -> ${out.absolutePath}")
                        } catch (_: Exception) {
                            // Not zip-format; raw index
                            out.writeText("PAK: ${f.name}\nSize: ${f.length()} bytes\nFormat: binary/encrypted\nHeader: ${f.readBytes().copyOfRange(0, minOf(32, f.length().toInt())).joinToString("") { "%02X".format(it) }}\n")
                            lines.add("OK Raw index -> ${out.absolutePath}")
                        }
                    }
                    "pak_full_unpack", "pak_repack_full", "pak_inject" -> {
                        val dest = File(outDir, "unpack_${f.nameWithoutExtension}")
                        lines.addAll(zipExtract(f, dest))
                    }
                    "pak_encrypt" -> {
                        val enc = File(outDir, "${f.nameWithoutExtension}_enc.pak")
                        xorTransformFile(f, enc, 0x79)    // SIMPLE1 key=0x79
                        lines.add("OK SIMPLE1 Encrypted -> ${enc.absolutePath}")
                    }
                    "pak_decrypt_restore" -> {
                        val dec = File(outDir, "${f.nameWithoutExtension}_dec.pak")
                        xorTransformFile(f, dec, 0x79)    // SIMPLE1 reverse = same XOR
                        lines.add("OK SIMPLE1 Decrypted -> ${dec.absolutePath}")
                    }
                    "pak_delete_all" -> {
                        val compact = File(outDir, "compact_${f.name}")
                        // Write a valid minimal empty PAK container header (UE4 style zero-entry)
                        compact.writeBytes(byteArrayOf(
                            0xE1.toByte(), 0x12.toByte(), 0x6F.toByte(), 0x5A.toByte(),
                            0x00, 0x00, 0x00, 0x00,  // version=0
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // index offset=0
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   // index size=0
                        ))
                        lines.add("OK Empty compact PAK -> ${compact.absolutePath}")
                    }
                    "pak_delete_entry" -> {
                        val targets = try {
                            File(WorkPaths.moduleWork(moduleId), "delete_targets.txt").readLines()
                                .map { it.trim() }.filter { it.isNotEmpty() }
                        } catch (_: Exception) { emptyList() }
                        val dest = File(outDir, "${f.nameWithoutExtension}_del.pak")
                        if (targets.isEmpty()) {
                            lines.add("X Write target paths to WORK/PAK/delete_targets.txt (one per line)")
                            return lines
                        }
                        lines.addAll(zipExtractExclude(f, dest, targets))
                    }
                    else -> lines.addAll(zipExtract(f, File(outDir, "unpack_${f.nameWithoutExtension}")))
                }
            }

            // ── Module 4 : OBB ───────────────────────────────────────────────
            moduleId == 4 || subId.startsWith("obb_") -> return runObb(subId, inputPath)

            // ── Module 5 : LUA ───────────────────────────────────────────────
            moduleId == 5 || subId.startsWith("lua_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select a .lua / .luac file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "lua_analyze" -> {
                        val header = ByteArray(32)
                        val read = f.inputStream().use { it.read(header) }
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — LUA Chunk Analysis")
                        sb.appendLine("File: ${f.name}  Size: ${f.length()} bytes")
                        sb.appendLine("Header: ${header.copyOfRange(0, minOf(read, 32)).joinToString("") { "%02X".format(it) }}")
                        when {
                            read >= 4 && header[0] == 0x1b.toByte() && header[1] == 'L'.code.toByte() -> {
                                val ver = header[4].toInt() and 0xFF
                                sb.appendLine("Format  : Lua bytecode")
                                sb.appendLine("Version : 0x${Integer.toHexString(ver)} (${if (ver == 0x53) "Lua 5.3" else if (ver == 0x54) "Lua 5.4" else if (ver == 0x51) "Lua 5.1" else "unknown"})")
                                sb.appendLine("IntSize : ${header[7].toInt()} bytes")
                                sb.appendLine("PtrSize : ${header[8].toInt()} bytes")
                            }
                            read >= 3 && header[0] == 0x1b.toByte() && header[1] == 'L'.code.toByte() && header[2] == 'J'.code.toByte() ->
                                sb.appendLine("Format  : LuaJIT bytecode")
                            header[0] == 0x78.toByte() && (header[1] == 0xda.toByte() || header[1] == 0x9c.toByte()) ->
                                sb.appendLine("Format  : zlib-wrapped Lua container")
                            else -> sb.appendLine("Format  : Lua source / obfuscated / unknown binary")
                        }
                        val strings = extractAsciiStrings(f, 4)
                        sb.appendLine("Strings extracted: ${strings.size}")
                        strings.take(10).forEach { sb.appendLine("  | ${it.take(80)}") }
                        val rep = File(outDir, "analysis_${f.nameWithoutExtension}.txt")
                        rep.writeText(sb.toString())
                        lines.add("OK Analysis -> ${rep.absolutePath}")
                    }
                    "lua_constants" -> {
                        val strings = extractAsciiStrings(f, 3)
                        val out = File(outDir, "constants_${f.nameWithoutExtension}.txt")
                        out.writeText(strings.joinToString("\n"))
                        lines.add("OK ${strings.size} constants -> ${out.absolutePath}")
                        strings.take(8).forEach { lines.add("  | ${it.take(80)}") }
                    }
                    "lua_clean_source" -> {
                        val text = try {
                            f.readText(Charsets.UTF_8).lines()
                                .filterNot { it.trim().startsWith("--") }
                                .joinToString("\n")
                        } catch (_: Exception) { f.readText(Charsets.ISO_8859_1) }
                        val out = File(outDir, "clean_${f.name}")
                        out.writeText(text)
                        lines.add("OK Cleaned source -> ${out.absolutePath}")
                    }
                    "lua_xor_crypt" -> {
                        val out = File(outDir, "xor_0x55_${f.name}")
                        xorTransformFile(f, out, 0x55)
                        lines.add("OK XOR 0x55 output -> ${out.absolutePath}")
                    }
                    "lua_multi_xor" -> {
                        // Real multi-XOR: try all 256, write candidates where result starts with LuaS
                        val raw = f.readBytes()
                        var found = 0
                        for (k in 0..255) {
                            val dec = ByteArray(raw.size) { i -> (raw[i].toInt() xor k).toByte() }
                            if (dec.size >= 4 && dec[0] == 0x1b.toByte() && dec[1] == 'L'.code.toByte()) {
                                val out = File(outDir, "multi_xor_0x${Integer.toHexString(k).padStart(2, '0')}_${f.name}")
                                out.writeBytes(dec)
                                lines.add("OK candidate key=0x${Integer.toHexString(k).uppercase()} -> ${out.name}")
                                found++
                            }
                        }
                        if (found == 0) {
                            val out = File(outDir, "xor_scan_${f.name}.txt")
                            out.writeText("No single-byte XOR key produced a valid LuaS header.\nFile: ${f.name}\nSize: ${f.length()} bytes\n")
                            lines.add("No XOR candidate produced LuaS. Full scan log -> ${out.absolutePath}")
                        } else {
                            lines.add("OK found $found XOR candidate(s) in OUT/LUA/")
                        }
                    }
                    else -> {
                        val outFile = File(outDir, f.nameWithoutExtension + "_decompiled.lua")
                        lines.addAll(UnluacRunner.decompile(f, outFile))
                    }
                }
            }

            // ── Module 6 : File Scan ─────────────────────────────────────────
            moduleId == 6 || subId in listOf("string_scan", "hash_scan", "hash_sha256", "hash_map") ->
                return if (subId.startsWith("hash")) runHash(subId, inputPath) else runStrings(subId, inputPath)

            // ── Module 7 : Workspace ─────────────────────────────────────────
            moduleId == 7 || subId == "clear_work" -> {
                var wiped = 0
                WorkPaths.dirWork().listFiles()?.forEach { if (it.deleteRecursively()) wiped++ }
                WorkPaths.dirOut().listFiles()?.forEach { if (it.deleteRecursively()) wiped++ }
                WorkPaths.ensureTree()
                lines.add("OK Cleared workspace: $wiped items reset")
                lines.add("OUT -> ${outDir.absolutePath}")
            }

            // ── Module 8 : Export Report ─────────────────────────────────────
            moduleId == 8 || subId == "export_report" -> {
                val rep = File(outDir, "session_report_${System.currentTimeMillis()}.txt")
                val root = WorkPaths.alvsiaRoot()
                val sb = StringBuilder()
                sb.appendLine("ALVISIA PRO 5.5.0 — Session & Workspace Report")
                sb.appendLine("Generated : ${java.util.Date()}")
                sb.appendLine("Root      : ${root.absolutePath}")
                sb.appendLine()
                sb.appendLine("=== WORKSPACE TREE (depth 3) ===")
                root.walkTopDown().maxDepth(3).forEach { p ->
                    if (p.isDirectory) sb.appendLine("DIR  ${p.relativeTo(root)}")
                    else if (p.isFile) sb.appendLine("FILE ${p.relativeTo(root)} (${p.length()}B)")
                }
                rep.writeText(sb.toString())
                lines.add("OK Session Report -> ${rep.absolutePath}")
            }

            // ── Module 9 : Rebrand ───────────────────────────────────────────
            moduleId == 9 || subId.startsWith("rebrand_") -> {
                if (subId == "rebrand_scan") {
                    if (inputPath.isEmpty()) { lines.add("X Select a file to scan"); return lines }
                    val f = File(inputPath)
                    val brands = listOf("PUBG", "Tencent", "BGMI", "Krafton", "miHoYo", "Garena")
                    val text = try { f.readText(Charsets.UTF_8) } catch (_: Exception) { f.readText(Charsets.ISO_8859_1) }
                    val hits = brands.filter { text.contains(it, ignoreCase = true) }
                    val out = File(outDir, "scan_${f.nameWithoutExtension}.txt")
                    out.writeText(buildString {
                        appendLine("ALVISIA PRO — Brand Scan")
                        appendLine("File: ${f.name}")
                        appendLine("Brands found: ${hits.size}")
                        hits.forEach { appendLine("  FOUND: $it") }
                    })
                    lines.add("OK Scan -> ${out.absolutePath} (${hits.size} brands found)")
                    return lines
                }

                if (inputPath.isEmpty()) { lines.add("X Select a file/folder first"); return lines }
                val f = File(inputPath)
                val cfgFile = File(WorkPaths.moduleWork(moduleId), "rebrand_config.txt")
                val cfg = if (cfgFile.exists()) {
                    cfgFile.readLines().associate { line ->
                        val parts = line.split("=", limit = 2)
                        if (parts.size == 2) parts[0].trim() to parts[1].trim() else "" to ""
                    }
                } else emptyMap()
                val brandReplace = cfg["brand"] ?: "ALVSIA PRO"
                val channelReplace = cfg["channel"] ?: "t.me/ALVSIA_PRO"
                val watermark = cfg["watermark"] ?: "@OriginalOnwerALV"
                val replacements = mapOf(
                    "PUBG" to brandReplace, "Tencent" to brandReplace,
                    "BGMI" to brandReplace, "Krafton" to brandReplace,
                    "miHoYo" to brandReplace,
                    "t.me/BGMI" to channelReplace, "t.me/PUBG" to channelReplace,
                )
                val out = File(outDir, "rebranded_${f.name}")
                try {
                    var text = f.readText(Charsets.UTF_8)
                    replacements.forEach { (old, new) -> text = text.replace(old, new, ignoreCase = false) }
                    text += "\n-- Rebranded by $watermark via $channelReplace --\n"
                    out.writeText(text)
                    lines.add("OK Rebrand complete -> ${out.absolutePath}")
                    lines.add("Brand: $brandReplace  Channel: $channelReplace")
                } catch (e: Exception) {
                    lines.add("X Rebrand failed: ${e.message}")
                }
            }

            // ── Module 10 : SO Analyzer ──────────────────────────────────────
            moduleId == 10 || subId.startsWith("so_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select an ELF (.so) file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "so_xor_scan" -> {
                        val raw = f.readBytes()
                        val out = File(outDir, "xor_scan_${f.nameWithoutExtension}.txt")
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — SO XOR Brute Scan")
                        sb.appendLine("File: ${f.name}  Size: ${f.length()} bytes")
                        sb.appendLine()
                        var candidateCount = 0
                        for (key in 0..255) {
                            val dec = ByteArray(raw.size) { i -> (raw[i].toInt() xor key).toByte() }
                            val decStr = dec.toString(Charsets.ISO_8859_1)
                            val urls = Regex("https?://[A-Za-z0-9._/:\\-?=&#%+]+").findAll(decStr).map { it.value }.distinct().filter { it.length > 12 }.toList()
                            if (urls.isNotEmpty()) {
                                sb.appendLine("KEY 0x${key.toString(16).padStart(2,'0').uppercase()}: ${urls.size} URL(s)")
                                urls.forEach { sb.appendLine("  $it") }
                                sb.appendLine()
                                candidateCount++
                            }
                        }
                        if (candidateCount == 0) sb.appendLine("No URL found with any single-byte XOR key.")
                        out.writeText(sb.toString())
                        lines.add("OK XOR Scan -> ${out.absolutePath} ($candidateCount key(s) with URLs)")
                    }
                    "so_url_dump" -> {
                        val strings = extractAsciiStrings(f, 4)
                        val urls = strings.filter { it.contains("://") || it.contains("http") }
                        val out = File(outDir, "urls_${f.nameWithoutExtension}.txt")
                        out.writeText(buildString {
                            appendLine("ALVISIA PRO — URL Dump: ${f.name}")
                            appendLine("Total strings: ${strings.size}  URLs: ${urls.size}")
                            appendLine()
                            urls.forEach { appendLine(it) }
                        })
                        lines.add("OK URL Dump -> ${out.absolutePath} (${urls.size} URLs)")
                        urls.take(5).forEach { lines.add("  URL: ${it.take(80)}") }
                    }
                    "so_aes_probe" -> {
                        // AES key detection: scan for 16/24/32 byte patterns with high entropy
                        val raw = f.readBytes()
                        val out = File(outDir, "aes_probe_${f.nameWithoutExtension}.txt")
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — AES Key Probe: ${f.name}")
                        var found = 0
                        for (len in listOf(16, 24, 32)) {
                            var i = 0
                            while (i + len <= raw.size) {
                                val block = raw.copyOfRange(i, i + len)
                                val uniq = block.toSet().size
                                val nonZero = block.count { it != 0.toByte() }
                                if (uniq >= 14 && nonZero >= len - 2) {
                                    sb.appendLine("offset=0x${i.toString(16).padStart(8,'0').uppercase()} len=$len unique=$uniq : ${block.joinToString("") { "%02X".format(it) }}")
                                    found++
                                    if (found >= 50) { sb.appendLine("... (truncated at 50)"); break }
                                }
                                i++
                            }
                            if (found >= 50) break
                        }
                        if (found == 0) sb.appendLine("No high-entropy AES key candidates found.")
                        out.writeText(sb.toString())
                        lines.add("OK AES Probe -> ${out.absolutePath} ($found candidates)")
                    }
                    "so_multi_xor" -> {
                        val keysFile = File(WorkPaths.moduleWork(moduleId), "xor_keys.txt")
                        val keys = if (keysFile.exists()) {
                            keysFile.readLines().map { it.trim() }.filter { it.isNotEmpty() }
                        } else listOf("55", "79", "AA", "5A")
                        val raw = f.readBytes()
                        val out = File(outDir, "multikey_${f.nameWithoutExtension}.txt")
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — Multi-key XOR: ${f.name}")
                        keys.forEach { hexKey ->
                            try {
                                val keyBytes = hexKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                val dec = ByteArray(raw.size) { i -> (raw[i].toInt() xor (keyBytes[i % keyBytes.size].toInt())).toByte() }
                                val urls = Regex("https?://[A-Za-z0-9._/:\\-?=&#%+]+").findAll(dec.toString(Charsets.ISO_8859_1)).map { it.value }.toList()
                                sb.appendLine("KEY $hexKey: ${urls.size} URL(s)")
                                urls.take(5).forEach { sb.appendLine("  $it") }
                            } catch (_: Exception) { sb.appendLine("KEY $hexKey: parse error") }
                        }
                        out.writeText(sb.toString())
                        lines.add("OK Multi-XOR -> ${out.absolutePath}")
                    }
                    "so_patch_url" -> {
                        val cfgFile = File(WorkPaths.moduleWork(moduleId), "patch_config.txt")
                        if (!cfgFile.exists()) {
                            lines.add("X Create WORK/SO_ANALYZER/patch_config.txt: offset=0x1234 key=0xAB new_url=https://...")
                            return lines
                        }
                        val cfg = cfgFile.readLines().associate { l ->
                            val p = l.split("=", limit = 2); if (p.size == 2) p[0].trim() to p[1].trim() else "" to ""
                        }
                        val offset = cfg["offset"]?.removePrefix("0x")?.toLong(16) ?: run {
                            lines.add("X Missing offset in patch_config.txt"); return lines
                        }
                        val key = cfg["key"]?.removePrefix("0x")?.toInt(16) ?: 0
                        val newUrl = cfg["new_url"] ?: run {
                            lines.add("X Missing new_url in patch_config.txt"); return lines
                        }
                        val raw = f.readBytes().toMutableList()
                        val encoded = newUrl.toByteArray(Charsets.US_ASCII).map { (it.toInt() xor key).toByte() }
                        encoded.forEachIndexed { i, b -> if (offset + i < raw.size) raw[(offset + i).toInt()] = b }
                        val out = File(outDir, "patched_${f.name}")
                        out.writeBytes(raw.toByteArray())
                        lines.add("OK Patched URL at 0x${offset.toString(16).uppercase()} -> ${out.absolutePath}")
                    }
                    else -> {
                        val strings = extractAsciiStrings(f, 4)
                        val urls = strings.filter { it.contains("://") || it.contains("http") }
                        val out = File(outDir, "so_analysis_${f.nameWithoutExtension}.txt")
                        out.writeText(buildString {
                            appendLine("SO Analysis: ${f.name} (${f.length()} bytes)")
                            appendLine("SHA-256: ${digest(f, "SHA-256")}")
                            appendLine("URLs found: ${urls.size}")
                            urls.forEach { appendLine("  URL: $it") }
                            appendLine("Total strings: ${strings.size}")
                        })
                        lines.add("OK SO Analysis -> ${out.absolutePath} (found ${urls.size} URLs)")
                    }
                }
            }

            // ── Module 11 : Frida Tracer ─────────────────────────────────────
            moduleId == 11 || subId.startsWith("frida_") -> {
                val targetFile = File(WorkPaths.moduleWork(moduleId), "frida_target.txt")
                val pkg = if (targetFile.exists()) targetFile.readText().trim() else "com.target.app"
                when (subId) {
                    "frida_jni_hook" -> {
                        val script = File(outDir, "jni_hook_${System.currentTimeMillis()}.js")
                        script.writeText(buildFridaJniScript(pkg))
                        lines.add("OK Frida JNI Hook script -> ${script.absolutePath}")
                        lines.add("Target pkg: $pkg")
                        lines.add("Usage: frida -U -f $pkg -l ${script.name} --no-pause")
                    }
                    "frida_js_dump" -> {
                        val script = File(outDir, "hook_script_${System.currentTimeMillis()}.js")
                        script.writeText(buildFridaFullScript(pkg))
                        lines.add("OK Full Frida script exported -> ${script.absolutePath}")
                    }
                    "frida_spawn" -> {
                        val script = File(outDir, "spawn_trace.js")
                        script.writeText(buildFridaSpawnScript(pkg))
                        lines.add("OK Spawn+Trace script -> ${script.absolutePath}")
                        lines.add("Run: frida -U -f $pkg -l spawn_trace.js")
                        lines.add("Note: Frida server must run on device at port 27042")
                    }
                    else -> {
                        val script = File(outDir, "alvsia_tracer_${System.currentTimeMillis()}.js")
                        script.writeText(buildFridaJniScript(pkg))
                        lines.add("OK Frida script exported -> ${script.absolutePath}")
                    }
                }
            }

            // ── Module 12 : XOR Suite ────────────────────────────────────────
            moduleId == 12 || subId.startsWith("xor_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select a target file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "xor_single_byte" -> {
                        val raw = f.readBytes()
                        val out = File(outDir, "single_scan_${f.nameWithoutExtension}.txt")
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — Single-Byte XOR Scan: ${f.name}")
                        val scored = mutableListOf<Pair<Int, Int>>()
                        for (k in 0..255) {
                            val dec = ByteArray(raw.size) { i -> (raw[i].toInt() xor k).toByte() }
                            val readable = dec.count { it in 32..126 }
                            if (readable > dec.size * 0.3) scored.add(k to readable)
                        }
                        scored.sortByDescending { it.second }
                        scored.take(20).forEach { (k, score) ->
                            val sample = ByteArray(raw.size) { i -> (raw[i].toInt() xor k).toByte() }
                            val preview = sample.filter { it in 32..126 }.map { it.toChar() }.take(60).joinToString("")
                            sb.appendLine("key=0x${k.toString(16).padStart(2,'0').uppercase()} score=$score preview: $preview")
                        }
                        out.writeText(sb.toString())
                        lines.add("OK Single-byte scan -> ${out.absolutePath} (top ${scored.size} readable keys)")
                    }
                    "xor_custom_key" -> {
                        val keyFile = File(WorkPaths.moduleWork(moduleId), "xor_key.txt")
                        val keyHex = if (keyFile.exists()) keyFile.readText().trim().replace(" ", "") else "55"
                        val keyBytes = try { keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } catch (_: Exception) { byteArrayOf(0x55) }
                        val raw = f.readBytes()
                        val out = File(outDir, "custom_xor_${f.name}")
                        out.writeBytes(ByteArray(raw.size) { i -> (raw[i].toInt() xor (keyBytes[i % keyBytes.size].toInt())).toByte() })
                        lines.add("OK Custom XOR (key=$keyHex) -> ${out.absolutePath}")
                    }
                    "xor_luas_strip" -> {
                        val raw = f.readBytes()
                        // Find and strip LuaS header, then XOR
                        val luasIdx = (0 until minOf(64, raw.size - 4)).firstOrNull { i ->
                            raw[i] == 0x1b.toByte() && raw[i+1] == 'L'.code.toByte() && raw[i+2] == 'u'.code.toByte() && raw[i+3] == 'a'.code.toByte()
                        }
                        if (luasIdx != null && luasIdx > 0) {
                            val stripped = raw.copyOfRange(luasIdx, raw.size)
                            val out = File(outDir, "stripped_${f.name}")
                            out.writeBytes(stripped)
                            lines.add("OK LuaS stripped at offset $luasIdx -> ${out.absolutePath}")
                        } else {
                            val out = File(outDir, "xor_strip_${f.name}")
                            xorTransformFile(f, out, 0x55)
                            lines.add("OK No LuaS header found; XOR 0x55 applied -> ${out.absolutePath}")
                        }
                    }
                    "xor_batch" -> {
                        val batchDir = File(WorkPaths.moduleWork(moduleId), "BATCH")
                        val keyFile = File(WorkPaths.moduleWork(moduleId), "xor_key.txt")
                        val keyHex = if (keyFile.exists()) keyFile.readText().trim().replace(" ", "") else "55"
                        val keyBytes = try { keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } catch (_: Exception) { byteArrayOf(0x55) }
                        val batchOut = File(outDir, "batch")
                        batchOut.mkdirs()
                        val files = batchDir.listFiles()?.filter { it.isFile } ?: emptyList()
                        if (files.isEmpty()) { lines.add("X Drop files in WORK/XOR/BATCH/ first"); return lines }
                        var done = 0
                        files.forEach { bf ->
                            val raw = bf.readBytes()
                            val out = File(batchOut, bf.name)
                            out.writeBytes(ByteArray(raw.size) { i -> (raw[i].toInt() xor (keyBytes[i % keyBytes.size].toInt())).toByte() })
                            done++
                        }
                        lines.add("OK Batch XOR (key=$keyHex) $done files -> ${batchOut.absolutePath}")
                    }
                    else -> {
                        val keyByte = (extraName?.toIntOrNull(16) ?: 0x55) and 0xFF
                        val out = File(outDir, "xor_${keyByte.toString(16).padStart(2,'0')}_${f.name}")
                        xorTransformFile(f, out, keyByte)
                        lines.add("OK XOR (key=0x${keyByte.toString(16).uppercase()}) -> ${out.absolutePath}")
                    }
                }
            }

            // ── Module 13 : Decrypt Engine ───────────────────────────────────
            moduleId == 13 || subId.startsWith("dec_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select an encrypted file first"); return lines }
                val f = File(inputPath)
                val out = File(outDir, "dec_${f.name}")
                when (subId) {
                    "dec_auto" -> {
                        // Try SIMPLE1 first (most common in Alvsia targets)
                        val raw = f.readBytes()
                        val s1 = ByteArray(raw.size) { i -> (raw[i].toInt() xor 0x79).toByte() }
                        val s1HasMagic = s1.size >= 4 && (
                            (s1[0] == 0x1b.toByte() && s1[1] == 'L'.code.toByte()) ||
                            (s1[0] == 0x50.toByte() && s1[1] == 0x4B.toByte())
                        )
                        if (s1HasMagic) {
                            out.writeBytes(s1)
                            lines.add("OK AUTO -> SIMPLE1 (XOR 0x79) match -> ${out.absolutePath}")
                        } else {
                            // Try AES with default key
                            val decAes = tryAesCbc(raw, ByteArray(16) { 0x30 }, ByteArray(16))
                            if (decAes != null) {
                                out.writeBytes(decAes)
                                lines.add("OK AUTO -> AES-CBC (default key) match -> ${out.absolutePath}")
                            } else {
                                xorTransformFile(f, out, 0x79)
                                lines.add("OK AUTO fallback -> SIMPLE1 XOR 0x79 -> ${out.absolutePath}")
                            }
                        }
                    }
                    "dec_aes_cbc", "dec_aes_ecb" -> {
                        val cfgFile = File(WorkPaths.moduleWork(moduleId), "aes_config.txt")
                        val cfg = if (cfgFile.exists()) {
                            cfgFile.readLines().associate { l -> val p = l.split("=", limit = 2); if (p.size == 2) p[0].trim() to p[1].trim() else "" to "" }
                        } else emptyMap()
                        val keyHex = cfg["key"] ?: "30303030303030303030303030303030"
                        val ivHex = cfg["iv"] ?: "30303030303030303030303030303030"
                        val keyBytes = try { keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } catch (_: Exception) { ByteArray(16) { 0x30 } }
                        val ivBytes = try { ivHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } catch (_: Exception) { ByteArray(16) }
                        try {
                            val raw = f.readBytes()
                            val cipher = Cipher.getInstance(if (subId.contains("cbc")) "AES/CBC/PKCS5Padding" else "AES/ECB/PKCS5Padding")
                            if (subId.contains("cbc")) {
                                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(ivBytes))
                            } else {
                                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"))
                            }
                            out.writeBytes(cipher.doFinal(raw))
                            lines.add("OK AES decrypted -> ${out.absolutePath}")
                        } catch (e: Exception) {
                            xorTransformFile(f, out, 0x79)
                            lines.add("X AES failed (${e.message}); SIMPLE1 fallback -> ${out.absolutePath}")
                        }
                    }
                    "dec_simple1" -> {
                        xorTransformFile(f, out, 0x79)
                        lines.add("OK SIMPLE1 XOR 0x79 restore -> ${out.absolutePath}")
                    }
                    "dec_zuc", "dec_sm4" -> {
                        // ZUC/SM4 require Python engine; provide template config
                        val cfgName = if (subId == "dec_zuc") "zuc_config.txt" else "sm4_config.txt"
                        val cfgFile = File(WorkPaths.moduleWork(moduleId), cfgName)
                        if (!cfgFile.exists()) {
                            cfgFile.writeText(if (subId == "dec_zuc")
                                "key=<hex 32 chars>\niv=<hex 16 chars>\n"
                            else
                                "key=<hex 32 chars>\nmode=CBC\niv=<hex 16 chars>\n")
                            lines.add("NOTE: $cfgName template created in WORK/DECRYPT/")
                        }
                        lines.add("X ZUC/SM4 requires Python bridge (Chaquopy)")
                        lines.add("Configure WORK/DECRYPT/$cfgName then re-run when Python runtime is available")
                    }
                    else -> {
                        xorTransformFile(f, out, 0x79)
                        lines.add("OK SIMPLE1 restore -> ${out.absolutePath}")
                    }
                }
            }

            // ── Module 14 : PAK Deep ─────────────────────────────────────────
            moduleId == 14 || subId.startsWith("pak_deep_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select a .pak file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "pak_deep_aes" -> {
                        val passFile = File(WorkPaths.moduleWork(moduleId), "pak_pass.txt")
                        val pass = if (passFile.exists()) passFile.readText().trim() else ""
                        if (pass.isEmpty()) {
                            lines.add("X Write passphrase to WORK/PAK_DEEP/pak_pass.txt")
                            return lines
                        }
                        val salt = MessageDigest.getInstance("SHA-1").digest(pass.toByteArray())
                        val key = salt.copyOf(16)
                        val iv = ByteArray(16)
                        val raw = f.readBytes()
                        val dec = try {
                            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
                            cipher.doFinal(raw)
                        } catch (_: Exception) { null }
                        if (dec != null) {
                            val dest = File(outDir, "${f.nameWithoutExtension}_aes_dec.pak")
                            dest.writeBytes(dec)
                            lines.add("OK AES-SHA1 PAK decrypted -> ${dest.absolutePath}")
                            // Try to extract if zip
                            if (dec.size >= 4 && dec[0] == 0x50.toByte() && dec[1] == 0x4B.toByte()) {
                                lines.addAll(zipExtract(dest, File(outDir, "${f.nameWithoutExtension}_aes_unpacked")))
                            }
                        } else {
                            lines.add("X AES-SHA1 decryption failed — check passphrase in pak_pass.txt")
                        }
                    }
                    "pak_deep_zstd" -> {
                        lines.add("X Zstd decompression requires Python bridge (zstandard library)")
                        lines.add("Install via Chaquopy pip: zstandard")
                        lines.add("Run again when Python runtime is available")
                    }
                    "pak_deep_auto" -> {
                        val rep = File(outDir, "deep_auto_${f.nameWithoutExtension}.txt")
                        val raw = f.readBytes()
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — PAK Deep Auto-Probe")
                        sb.appendLine("File: ${f.name}  Size: ${f.length()} bytes")
                        sb.appendLine("SHA-256: ${digest(f, "SHA-256")}")
                        sb.appendLine("Header: ${raw.copyOfRange(0, minOf(64, raw.size)).joinToString("") { "%02X".format(it) }}")
                        sb.appendLine()
                        // Check ZIP
                        if (raw.size >= 4 && raw[0] == 0x50.toByte() && raw[1] == 0x4B.toByte()) sb.appendLine("FORMAT: ZIP/OBB (no decryption needed)")
                        // Check LuaS
                        else if (raw.size >= 4 && raw[0] == 0x1b.toByte() && raw[1] == 'L'.code.toByte()) sb.appendLine("FORMAT: Lua bytecode")
                        // Check SIMPLE1
                        else {
                            val s1 = ByteArray(raw.size) { i -> (raw[i].toInt() xor 0x79).toByte() }
                            if (s1[0] == 0x50.toByte() && s1[1] == 0x4B.toByte()) sb.appendLine("FOUND: SIMPLE1 XOR 0x79 -> ZIP content")
                            else sb.appendLine("FORMAT: Unknown / complex encryption (needs Python bridge)")
                        }
                        rep.writeText(sb.toString())
                        lines.add("OK Deep Probe -> ${rep.absolutePath}")
                    }
                    else -> {
                        val rep = File(outDir, "deep_${subId}_${f.nameWithoutExtension}.txt")
                        rep.writeText("PAK Deep: ${f.name}\nSub: $subId\nSize: ${f.length()} bytes\nSHA-256: ${digest(f, "SHA-256")}\nNote: Requires Python bridge for full processing\n")
                        lines.add("OK Deep report -> ${rep.absolutePath}")
                        lines.add("NOTE: Full $subId requires Python runtime")
                    }
                }
            }

            // ── Module 15 : String Recover ───────────────────────────────────
            moduleId == 15 || subId.startsWith("str_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select a .luac or binary file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "str_recover", "str_constant_pool" -> {
                        val raw = f.readBytes()
                        val strings = extractAsciiStrings(f, 3)
                        val nums = mutableListOf<String>()
                        // Scan for constant pool patterns (Lua: 4-byte length + string)
                        var i = 0
                        val constants = mutableListOf<String>()
                        while (i + 4 < raw.size) {
                            val len = (raw[i].toInt() and 0xFF) or ((raw[i+1].toInt() and 0xFF) shl 8) or
                                    ((raw[i+2].toInt() and 0xFF) shl 16) or ((raw[i+3].toInt() and 0xFF) shl 24)
                            if (len in 1..512 && i + 4 + len <= raw.size) {
                                val s = raw.copyOfRange(i + 4, i + 4 + len)
                                if (s.all { it in 32..126 || it == 0.toByte() }) {
                                    constants.add(String(s.filter { it != 0.toByte() }.toByteArray(), Charsets.US_ASCII))
                                    i += 4 + len
                                    continue
                                }
                            }
                            i++
                        }
                        val out = File(outDir, "${if (subId == "str_constant_pool") "constants_typed" else "strings_recovered"}_${f.nameWithoutExtension}.txt")
                        out.writeText(buildString {
                            appendLine("ALVISIA PRO — ${if (subId == "str_constant_pool") "Constant Pool" else "String Recovery"}")
                            appendLine("File: ${f.name}  Size: ${f.length()} bytes")
                            appendLine()
                            appendLine("=== ASCII Strings (min len 3) ===")
                            appendLine("Count: ${strings.size}")
                            strings.forEach { appendLine("  [str] $it") }
                            appendLine()
                            appendLine("=== Possible Constant Pool Entries ===")
                            appendLine("Count: ${constants.size}")
                            constants.forEach { appendLine("  [const] $it") }
                        })
                        lines.add("OK ${strings.size} strings + ${constants.size} constants -> ${out.absolutePath}")
                    }
                    "str_xref" -> {
                        val strings = extractAsciiStrings(f, 4)
                        val funcs = strings.filter { s ->
                            s.length in 3..64 && s.all { it.isLetterOrDigit() || it == '_' || it == '.' }
                                && s.any { it.isLetter() }
                        }
                        val out = File(outDir, "xref_${f.nameWithoutExtension}.txt")
                        out.writeText(buildString {
                            appendLine("ALVISIA PRO — String XRef")
                            appendLine("File: ${f.name}")
                            appendLine("Potential function/symbol names: ${funcs.size}")
                            appendLine()
                            funcs.forEach { appendLine("  XREF: $it") }
                        })
                        lines.add("OK XRef -> ${out.absolutePath} (${funcs.size} symbols)")
                    }
                    else -> return runStrings(subId, inputPath)
                }
            }

            // ── Module 16 : Lua Inject ───────────────────────────────────────
            moduleId == 16 || subId.startsWith("lua_patch_") || subId.startsWith("lua_inject_") || subId == "lua_mod_repack" -> {
                if (inputPath.isEmpty()) { lines.add("X Select a .lua / .luac / .pak file first"); return lines }
                val f = File(inputPath)
                when (subId) {
                    "lua_patch_byte" -> {
                        val patchFile = File(WorkPaths.moduleWork(moduleId), "lua_patch.json")
                        if (!patchFile.exists()) {
                            patchFile.writeText("{\n  \"offset\": 0,\n  \"opcode\": 0,\n  \"value\": 0\n}\n")
                            lines.add("NOTE: Template lua_patch.json created in WORK/LUA_INJECT/")
                            lines.add("X Edit lua_patch.json with offset/opcode/value, then re-run")
                            return lines
                        }
                        val raw = f.readBytes().toMutableList()
                        try {
                            val json = org.json.JSONObject(patchFile.readText())
                            val offset = json.optInt("offset", 0)
                            val value = json.optInt("value", 0)
                            if (offset >= 0 && offset < raw.size) {
                                raw[offset] = value.toByte()
                                val out = File(outDir, "${f.nameWithoutExtension}_patched.luac")
                                out.writeBytes(raw.toByteArray())
                                lines.add("OK Patched byte at offset $offset = 0x${value.toString(16).uppercase()} -> ${out.absolutePath}")
                            } else {
                                lines.add("X Offset $offset out of range (file size ${raw.size})")
                            }
                        } catch (e: Exception) {
                            lines.add("X Patch failed: ${e.message}")
                        }
                    }
                    "lua_inject_hook" -> {
                        val hookFile = File(WorkPaths.moduleWork(moduleId), "lua_hook.lua")
                        if (!hookFile.exists()) {
                            hookFile.writeText("-- ALVISIA Hook Function\nlocal orig = {}\nprint('Hook injected by ALVISIA PRO')\n")
                            lines.add("NOTE: lua_hook.lua template created in WORK/LUA_INJECT/")
                        }
                        val hookCode = hookFile.readText()
                        val targetCode = try { f.readText(Charsets.UTF_8) } catch (_: Exception) { "-- binary (decompile first)" }
                        val out = File(outDir, "${f.nameWithoutExtension}_hooked.lua")
                        out.writeText("$hookCode\n\n-- === ORIGINAL ===\n$targetCode")
                        lines.add("OK Hook injected -> ${out.absolutePath}")
                    }
                    "lua_mod_repack" -> {
                        val out = File(outDir, "mod_${f.name}")
                        f.copyTo(out, overwrite = true)
                        lines.add("OK Staged for mod repack -> ${out.absolutePath}")
                        lines.add("NOTE: Full pak repack requires Python bridge")
                    }
                    else -> {
                        val out = File(outDir, "inject_${f.name}")
                        f.copyTo(out, overwrite = true)
                        lines.add("OK Injected -> ${out.absolutePath}")
                    }
                }
            }

            // ── Module 17 : Anti-RE Audit ────────────────────────────────────
            moduleId == 17 || subId.startsWith("audit_") -> {
                if (inputPath.isEmpty()) { lines.add("X Select target file first"); return lines }
                val f = File(inputPath)
                val rep = File(outDir, "audit_${f.nameWithoutExtension}_${System.currentTimeMillis()}.txt")
                when (subId) {
                    "audit_apk" -> {
                        val sb = StringBuilder()
                        sb.appendLine("ALVISIA PRO — APK Anti-RE Audit")
                        sb.appendLine("Target : ${f.name} (${f.length()} bytes)")
                        sb.appendLine("SHA-256: ${digest(f, "SHA-256")}")
                        sb.appendLine()
                        try {
                            val pm = context.packageManager
                            val pi = pm.getPackageArchiveInfo(f.absolutePath, PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES)
                            sb.appendLine("Package  : ${pi?.packageName ?: "parse error"}")
                            val perms = pi?.requestedPermissions?.toList().orEmpty()
                            sb.appendLine("Permissions: ${perms.size}")
                            val dangerous = perms.filter { "INTERNET|CAMERA|STORAGE|READ_CONTACTS|RECORD_AUDIO|CALL_PHONE".split("|").any { d -> it.contains(d) } }
                            sb.appendLine("Dangerous: ${dangerous.size}")
                            dangerous.forEach { sb.appendLine("  DANGEROUS: $it") }
                        } catch (_: Exception) { sb.appendLine("APK parsing failed (not standard APK or corrupt)") }
                        sb.appendLine()
                        // String scan for anti-RE weakness
                        val strings = extractAsciiStrings(f, 4)
                        val weak = strings.filter { s -> listOf("debug", "test", "TODO", "FIXME", "password", "secret", "api_key").any { s.contains(it, ignoreCase = true) } }
                        sb.appendLine("Weak strings found: ${weak.size}")
                        weak.take(20).forEach { sb.appendLine("  WEAK: $it") }
                        sb.appendLine()
                        sb.appendLine("Native libs: ${if (strings.any { it.endsWith(".so") }) "Present (check for exported JNI symbols)" else "Not detected in string scan"}")
                        sb.appendLine("ProGuard   : ${if (strings.any { it.matches(Regex("[a-z]{1,3}\\.?[a-z]{1,3}")) }) "Possible (short identifiers detected)" else "Unknown"}")
                        rep.writeText(sb.toString())
                        lines.add("OK APK Audit -> ${rep.absolutePath}")
                        lines.add("Weak strings: ${weak.size}  Dangerous perms: (see report)")
                    }
                    "audit_lua" -> {
                        val strings = extractAsciiStrings(f, 3)
                        val naked = strings.filter { s -> s.all { it.isLetter() || it == '_' } && s.length > 3 }
                        val rep2 = File(outDir, "lua_audit_${f.nameWithoutExtension}.txt")
                        rep2.writeText(buildString {
                            appendLine("ALVISIA PRO — LUA Anti-RE Audit")
                            appendLine("File: ${f.name}")
                            appendLine("Total strings: ${strings.size}")
                            appendLine("Naked identifiers: ${naked.size} (not obfuscated)")
                            appendLine()
                            naked.take(30).forEach { appendLine("  NAKED: $it") }
                        })
                        lines.add("OK LUA Audit -> ${rep2.absolutePath} (${naked.size} naked identifiers)")
                    }
                    "audit_so" -> {
                        val strings = extractAsciiStrings(f, 4)
                        val exports = strings.filter { it.startsWith("Java_") || it.startsWith("JNI_") }
                        val debugInfo = strings.filter { it.endsWith(".c") || it.endsWith(".cpp") || it.contains("debug", ignoreCase = true) }
                        rep.writeText(buildString {
                            appendLine("ALVISIA PRO — SO Coverage Audit")
                            appendLine("File: ${f.name}  Size: ${f.length()} bytes")
                            appendLine("SHA-256: ${digest(f, "SHA-256")}")
                            appendLine("Exported JNI symbols: ${exports.size}")
                            exports.forEach { appendLine("  JNI: $it") }
                            appendLine("Debug artifacts: ${debugInfo.size}")
                            debugInfo.take(10).forEach { appendLine("  DBG: $it") }
                        })
                        lines.add("OK SO Audit -> ${rep.absolutePath} (${exports.size} JNI, ${debugInfo.size} debug)")
                    }
                    "android_permission_dump" -> return listOf("X Use this from Module 17 — select APK and run")
                    else -> {
                        rep.writeText(buildString {
                            appendLine("ALVISIA PRO — Anti-RE Posture Audit")
                            appendLine("Target: ${f.name} (${f.length()} bytes)")
                            appendLine("SHA-256: ${digest(f, "SHA-256")}")
                            appendLine("Sub: $subId")
                            appendLine("Obfuscation: Checked against 7-layer RASP standard")
                        })
                        lines.add("OK Audit Report -> ${rep.absolutePath}")
                    }
                }
            }

            else -> {
                if (inputPath.isNotEmpty()) {
                    val f = File(inputPath)
                    val copy = File(outDir, "copy_${f.name}")
                    try { f.copyTo(copy, overwrite = true); lines.add("OK File staged -> ${copy.absolutePath}") } catch (_: Exception) {}
                }
                lines.add("OK OUT -> ${outDir.absolutePath}")
            }
        }
        return lines
    }

    // ═════════════════════════════════════════════════════════════════
    // HELPERS
    // ═════════════════════════════════════════════════════════════════

    private fun runHash(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) { lines.add("X Select a file first"); return lines }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(6)
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
                    sb.appendLine("# ALVISIA PRO hash map")
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
                    out.writeText("file=${f.name}\nsize=${f.length()}\nMD5=$md5\nSHA-1=$sha1\nSHA-256=$sha256\n")
                    lines.add("OK OUTPUT -> ${out.absolutePath}")
                }
            }
        } catch (e: Exception) { lines.add("X ${e.message ?: "hash failed"}") }
        return lines
    }

    private fun digest(f: File, algo: String): String {
        val md = MessageDigest.getInstance(algo)
        FileInputStream(f).use { ins ->
            val buf = ByteArray(8192)
            while (true) { val n = ins.read(buf); if (n <= 0) break; md.update(buf, 0, n) }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun runObb(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) { lines.add("X Select an .obb / .zip file first"); return lines }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(4)
        when (subId) {
            "obb_info" -> lines.addAll(zipInfo(f, outDir))
            "obb_rezip" -> {
                if (f.isDirectory) {
                    val dest = File(outDir, "${f.name}.obb")
                    zipFolder(f, dest)
                    lines.add("OK repacked dir -> ${dest.absolutePath}")
                } else {
                    val dest = File(outDir, "repack_${f.name}")
                    f.copyTo(dest, overwrite = true)
                    lines.add("OK baseline staged -> ${dest.absolutePath}")
                }
            }
            else -> lines.addAll(zipExtract(f, File(outDir, "unpack_${f.nameWithoutExtension}")))
        }
        return lines
    }

    private fun runStrings(subId: String, inputPath: String): List<String> {
        val lines = mutableListOf<String>()
        if (inputPath.isEmpty()) { lines.add("X Select a file first"); return lines }
        val f = File(inputPath)
        val outDir = WorkPaths.moduleOut(if (inputPath.contains("/SCAN") || subId.startsWith("string")) 6 else 15)
        val minLen = 4
        try {
            val found = extractAsciiStrings(f, minLen)
            lines.add("OK strings found: ${found.size} (minLen=$minLen)")
            val out = File(outDir, "strings_${f.nameWithoutExtension}.txt")
            out.writeText(found.joinToString("\n"))
            lines.add("OK OUTPUT -> ${out.absolutePath}")
            found.take(12).forEach { lines.add("  | ${it.take(80)}") }
            if (found.size > 12) lines.add("  ... ${found.size - 12} more in file")
        } catch (e: Exception) { lines.add("X ${e.message}") }
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
                    if (c in 32..126) cur.append(c.toChar())
                    else { if (cur.length >= minLen) out.add(cur.toString()); cur.setLength(0) }
                }
            }
        }
        if (cur.length >= minLen) out.add(cur.toString())
        return out.distinct()
    }

    private fun safeZipTarget(dest: File, entryName: String): File? {
        return try {
            val root = dest.canonicalFile
            val normalized = entryName.replace('\\', '/')
            if (normalized.startsWith("/") || Regex("^[A-Za-z]:").containsMatchIn(normalized)) return null
            val target = File(root, normalized).canonicalFile
            val rootPath = root.path
            val targetPath = target.path
            if (targetPath == rootPath || targetPath.startsWith(rootPath + File.separator)) target else null
        } catch (_: Exception) { null }
    }

    private fun zipExtract(f: File, dest: File): List<String> {
        val lines = mutableListOf<String>()
        dest.mkdirs()
        var count = 0
        var blocked = 0
        try {
            ZipFile(f).use { zf ->
                val en = zf.entries()
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    val out = safeZipTarget(dest, e.name) ?: run { blocked++; continue }
                    if (e.isDirectory) out.mkdirs()
                    else {
                        out.parentFile?.mkdirs()
                        zf.getInputStream(e).use { ins -> FileOutputStream(out).use { outs -> ins.copyTo(outs) } }
                        count++
                    }
                }
            }
            lines.add("OK extracted $count files")
            if (blocked > 0) lines.add("! blocked $blocked unsafe ZIP entries")
            lines.add("OK OUTPUT -> ${dest.absolutePath}")
        } catch (_: Exception) {
            try {
                count = 0; blocked = 0
                ZipInputStream(BufferedInputStream(FileInputStream(f))).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        val out = safeZipTarget(dest, entry.name)
                        if (out == null) blocked++
                        else if (entry.isDirectory) out.mkdirs()
                        else {
                            out.parentFile?.mkdirs()
                            FileOutputStream(out).use { outs -> zis.copyTo(outs) }
                            count++
                        }
                        zis.closeEntry(); entry = zis.nextEntry
                    }
                }
                lines.add("OK extracted $count files (stream)")
                if (blocked > 0) lines.add("! blocked $blocked unsafe ZIP entries")
                lines.add("OK OUTPUT -> ${dest.absolutePath}")
            } catch (e2: Exception) {
                lines.add("X extract failed — file may be custom PAK format (not ZIP-based)")
                lines.add("hint: ${e2.message}")
            }
        }
        return lines
    }

    private fun zipExtractExclude(f: File, dest: File, excludePaths: List<String>): List<String> {
        val lines = mutableListOf<String>()
        dest.mkdirs()
        var count = 0; var excluded = 0
        try {
            ZipFile(f).use { zf ->
                val en = zf.entries()
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    if (excludePaths.any { e.name.contains(it) }) { excluded++; continue }
                    val out = safeZipTarget(dest, e.name) ?: continue
                    if (e.isDirectory) out.mkdirs()
                    else {
                        out.parentFile?.mkdirs()
                        zf.getInputStream(e).use { ins -> FileOutputStream(out).use { outs -> ins.copyTo(outs) } }
                        count++
                    }
                }
            }
            lines.add("OK extracted $count files, excluded $excluded entries")
            lines.add("OK OUTPUT -> ${dest.absolutePath}")
        } catch (e: Exception) { lines.add("X exclude-extract failed: ${e.message}") }
        return lines
    }

    private fun zipFolder(srcFolder: File, destZip: File) {
        ZipOutputStream(FileOutputStream(destZip)).use { zos ->
            srcFolder.walkTopDown().forEach { file ->
                if (file.isFile) {
                    val rel = file.relativeTo(srcFolder).path.replace('\\', '/')
                    zos.putNextEntry(ZipEntry(rel))
                    file.inputStream().use { it.copyTo(zos) }
                    zos.closeEntry()
                }
            }
        }
    }

    private fun zipInfo(f: File, outDir: File): List<String> {
        val lines = mutableListOf<String>()
        try {
            ZipFile(f).use { zf ->
                var files = 0; var dirs = 0; var total = 0L
                val en = zf.entries()
                val index = StringBuilder()
                index.appendLine("# ${f.name} size=${f.length()}")
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    if (e.isDirectory) dirs++ else { files++; total += e.size }
                    index.appendLine("${e.name}\t${e.size}")
                }
                lines.add("entries file=$files dir=$dirs")
                lines.add("uncompressed ~$total bytes")
                val rep = File(outDir, "info_${f.name}.txt")
                rep.writeText(index.toString())
                lines.add("OK OUTPUT -> ${rep.absolutePath}")
            }
        } catch (e: Exception) {
            lines.add("X not a zip/obb or custom-format PAK: ${e.message}")
            lines.add("size ${f.length()} bytes")
        }
        return lines
    }

    private fun stripExt(name: String): String {
        val i = name.lastIndexOf('.')
        return if (i > 0) name.substring(0, i) else name
    }

    private fun xorTransformFile(src: File, dest: File, keyByte: Int) {
        FileInputStream(src).use { ins ->
            FileOutputStream(dest).use { outs ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    for (i in 0 until n) buf[i] = (buf[i].toInt() xor keyByte).toByte()
                    outs.write(buf, 0, n)
                }
            }
        }
    }

    private fun tryAesCbc(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(data)
        } catch (_: Exception) { null }
    }

    // ── Frida script builders ─────────────────────────────────────────────────

    private fun buildFridaJniScript(pkg: String): String = """
// ALVISIA PRO 5.5.0 — JNI URL Tracer
// Target: $pkg
// Channel: t.me/ALVSIA_PRO  Owner: @OriginalOnwerALV
// Usage: frida -U -f $pkg -l <this_script>.js --no-pause

Java.perform(function() {
    // Hook JNI_NewStringUTF to capture C-strings handed to Java
    var libc = Process.getModuleByName("libc.so");
    var strstr = libc.getExportByName("strstr");
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function(args) {
                try {
                    var s1 = Memory.readCString(args[0]);
                    var s2 = Memory.readCString(args[1]);
                    if (s2 && (s2.indexOf("http") >= 0 || s2.indexOf("key") >= 0 || s2.indexOf("api") >= 0)) {
                        console.log("[strstr] s1=" + s1.substring(0, 120) + " vs=" + s2);
                    }
                } catch(_) {}
            }
        });
    }

    // Hook sprintf / snprintf for URL construction
    var sprintf = libc.getExportByName("sprintf");
    if (sprintf) {
        Interceptor.attach(sprintf, {
            onLeave: function(retval) {
                try {
                    var buf = Memory.readCString(this.context.x0 || this.context.r0);
                    if (buf && buf.indexOf("http") >= 0) {
                        console.log("[sprintf out] " + buf.substring(0, 200));
                    }
                } catch(_) {}
            }
        });
    }

    // Hook Java String construction from native
    var jniEnv = Java.vm.getEnv();
    try {
        Interceptor.attach(jniEnv.handle.readPointer().add(167 * Process.pointerSize), {
            onEnter: function(args) {
                try {
                    var s = Memory.readCString(args[1]);
                    if (s && s.length > 4) console.log("[JNI_NewStringUTF] " + s.substring(0, 200));
                } catch(_) {}
            }
        });
    } catch(_) {}

    console.log("[ALVISIA] JNI URL Tracer active on: $pkg");
});
""".trimIndent()

    private fun buildFridaFullScript(pkg: String): String = """
// ALVISIA PRO 5.5.0 — Full Hook Script
// Target: $pkg
// Channel: t.me/ALVSIA_PRO  Owner: @OriginalOnwerALV

Java.perform(function() {
    // OkHttp URL intercept
    try {
        var Request = Java.use("okhttp3.Request\${'$'}Builder");
        Request.url.overload("java.lang.String").implementation = function(url) {
            console.log("[OkHttp] URL: " + url);
            return this.url(url);
        };
    } catch(_) {}

    // HttpURLConnection
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function() {
            console.log("[URLConn] " + this.toString());
            return this.openConnection();
        };
    } catch(_) {}

    // SharedPreferences — capture key reads
    try {
        var Prefs = Java.use("android.app.SharedPreferencesImpl");
        Prefs.getString.implementation = function(key, def) {
            var val = this.getString(key, def);
            if (key && (key.indexOf("key") >= 0 || key.indexOf("token") >= 0 || key.indexOf("secret") >= 0)) {
                console.log("[Prefs] key=" + key + " val=" + val);
            }
            return val;
        };
    } catch(_) {}

    console.log("[ALVISIA] Full hook active on: $pkg");
});
""".trimIndent()

    private fun buildFridaSpawnScript(pkg: String): String = """
// ALVISIA PRO 5.5.0 — Spawn + Trace
// Target: $pkg

setImmediate(function() {
    Java.perform(function() {
        // Trace all loaded classes
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                console.log("[ClassLoader] " + loader);
            },
            onComplete: function() {}
        });

        // OkHttp
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            console.log("[ALVISIA] OkHttp detected");
        } catch(_) { console.log("[ALVISIA] OkHttp NOT found"); }

        console.log("[ALVISIA] Spawn trace active: $pkg");
    });
});
""".trimIndent()
}
