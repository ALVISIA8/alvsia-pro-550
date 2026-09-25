package com.alvsia.pro.tool

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream

/**
 * Runs unluac.Main on Android ART — no external JVM required.
 * Jar is packaged as app dependency and dexed by R8/D8.
 */
object UnluacRunner {
    fun decompile(input: File, output: File): List<String> {
        val lines = mutableListOf<String>()
        if (!input.isFile) {
            return listOf("X input not found: ${input.absolutePath}")
        }
        output.parentFile?.mkdirs()
        val oldOut = System.out
        val oldErr = System.err
        val buf = ByteArrayOutputStream()
        val errBuf = ByteArrayOutputStream()
        val ps = PrintStream(buf, true, Charsets.UTF_8.name())
        val psErr = PrintStream(errBuf, true, Charsets.UTF_8.name())
        return try {
            System.setOut(ps)
            System.setErr(psErr)
            val cls = Class.forName("unluac.Main")
            val main = cls.getMethod("main", Array<String>::class.java)
            // CLI: unluac [options] file  → source on stdout
            main.invoke(null, arrayOf(input.absolutePath))
            ps.flush()
            psErr.flush()
            val text = buf.toString(Charsets.UTF_8.name())
            val err = errBuf.toString(Charsets.UTF_8.name())
            val trimmed = text.trim()
            val looksLikeLua = trimmed.isNotEmpty() &&
                (trimmed.contains("function") || trimmed.contains("local ") ||
                 trimmed.contains("return ") || trimmed.contains("if ") ||
                 trimmed.contains("while ") || trimmed.contains("for ") ||
                 trimmed.contains("--"))
            val looksLikeError = trimmed.startsWith("Error", ignoreCase = true) ||
                trimmed.startsWith("Exception", ignoreCase = true) ||
                trimmed.contains("decompil", ignoreCase = true) && trimmed.contains("failed", ignoreCase = true)
            if (looksLikeLua && !looksLikeError) {
                output.writeText(text, Charsets.UTF_8)
                lines.add("OK unluac ART -> ${output.absolutePath}")
                lines.add("bytes ${output.length()}")
            } else {
                output.delete()
                lines.add("X unluac produced no validated Lua source")
                if (err.isNotBlank()) lines.add(err.take(800))
                if (trimmed.isNotEmpty() && !looksLikeError) lines.add(trimmed.take(800))
            }
            lines
        } catch (t: Throwable) {
            val msg = t.cause?.message ?: t.message ?: t.javaClass.simpleName
            listOf("X unluac ART: $msg")
        } finally {
            System.setOut(oldOut)
            System.setErr(oldErr)
            try {
                ps.close()
                psErr.close()
            } catch (_: Exception) {
            }
        }
    }
}
