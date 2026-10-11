package com.alvsia.pro.tool

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.util.zip.Inflater

/**
 * Android ART Lua decompiler runner.
 *
 * Supports:
 * - normal Lua/LuaJIT bytecode
 * - 0x78DA chunked raw-DEFLATE Lua containers
 * - in-process unluac.Main
 *
 * No external JVM process is required.
 */
object UnluacRunner {

    private fun hasPrefix(data: ByteArray, prefix: ByteArray): Boolean {
        if (data.size < prefix.size) return false
        for (i in prefix.indices) {
            if (data[i] != prefix[i]) return false
        }
        return true
    }

    private fun unwrapChunkedLua(
        input: File,
        outputDir: File
    ): Pair<File?, String?> {

        val data = input.readBytes()

        if (data.size < 2 ||
            data[0] != 0x78.toByte() ||
            data[1] != 0xDA.toByte()
        ) {
            return input to null
        }

        val chunks = ByteArrayOutputStream()
        var pos = 0
        var count = 0

        while (true) {
            var marker = -1
            var i = pos

            while (i + 1 < data.size) {
                if (data[i] == 0x78.toByte() &&
                    data[i + 1] == 0xDA.toByte()
                ) {
                    marker = i
                    break
                }
                i++
            }

            if (marker < 0) break

            val inflater = Inflater(true)

            try {
                val start = marker + 2
                inflater.setInput(
                    data,
                    start,
                    data.size - start
                )

                val buf = ByteArray(64 * 1024)

                while (!inflater.finished()) {
                    val n = inflater.inflate(buf)

                    if (n > 0) {
                        chunks.write(buf, 0, n)
                    } else if (
                        inflater.needsDictionary() ||
                        inflater.needsInput()
                    ) {
                        break
                    }

                    if (chunks.size() > 256 * 1024 * 1024) {
                        throw IllegalStateException(
                            "decompressed Lua container exceeds 256 MiB"
                        )
                    }
                }

                if (!inflater.finished()) {
                    break
                }

                count++

                // Kotlin property access: remaining, NOT remaining()
                pos = data.size - inflater.remaining

            } catch (_: Exception) {
                break
            } finally {
                inflater.end()
            }
        }

        val payload = chunks.toByteArray()

        val validLua =
            hasPrefix(
                payload,
                byteArrayOf(
                    0x1B,
                    0x4C,
                    0x75,
                    0x61
                )
            )

        val validLuaJit =
            hasPrefix(
                payload,
                byteArrayOf(
                    0x1B,
                    0x4C,
                    0x4A
                )
            )

        if (count == 0 || (!validLua && !validLuaJit)) {
            return input to null
        }

        val normalized = File(
            outputDir,
            input.nameWithoutExtension + "_unwrapped.luac"
        )

        normalized.writeBytes(payload)

        return normalized to
            "container=chunked-raw-deflate " +
            "chunks=$count bytes=${payload.size}"
    }

    private fun invokeUnluac(input: File): Pair<String, String> {
        val oldOut = System.out
        val oldErr = System.err

        val buf = ByteArrayOutputStream()
        val errBuf = ByteArrayOutputStream()

        val ps = PrintStream(
            buf,
            true,
            Charsets.UTF_8.name()
        )

        val psErr = PrintStream(
            errBuf,
            true,
            Charsets.UTF_8.name()
        )

        try {
            System.setOut(ps)
            System.setErr(psErr)

            val cls = Class.forName("unluac.Main")
            val main = cls.getMethod(
                "main",
                Array<String>::class.java
            )

            main.invoke(
                null,
                arrayOf(input.absolutePath)
            )

            ps.flush()
            psErr.flush()

            return (
                buf.toString(Charsets.UTF_8.name())
                to
                errBuf.toString(Charsets.UTF_8.name())
            )

        } finally {
            System.setOut(oldOut)
            System.setErr(oldErr)

            ps.close()
            psErr.close()
        }
    }

    private fun looksLikeLua(text: String): Boolean {
        val t = text.trim()

        if (t.isEmpty()) return false

        val looksLua =
            t.contains("function") ||
            t.contains("local ") ||
            t.contains("return ") ||
            t.contains("if ") ||
            t.contains("while ") ||
            t.contains("for ") ||
            t.contains("repeat ") ||
            t.contains("do ") ||
            t.contains("--")

        val looksError =
            t.startsWith("Error", true) ||
            t.startsWith("Exception", true) ||
            t.startsWith("java.", true)

        return looksLua && !looksError
    }

    fun decompile(
        input: File,
        output: File
    ): List<String> {

        if (!input.isFile) {
            return listOf(
                "X input not found: ${input.absolutePath}"
            )
        }

        output.parentFile?.mkdirs()

        val normalizedResult =
            try {
                unwrapChunkedLua(
                    input,
                    output.parentFile ?: input.parentFile!!
                )
            } catch (t: Throwable) {
                input to
                    "container error: ${t.message}"
            }

        val normalized =
            normalizedResult.first ?: input

        val containerNote =
            normalizedResult.second

        val lines = mutableListOf<String>()

        if (containerNote != null) {
            lines.add(
                "OK LUA container -> $containerNote"
            )
        }

        return try {

            val (text, err) =
                invokeUnluac(normalized)

            if (looksLikeLua(text)) {

                output.writeText(
                    text,
                    Charsets.UTF_8
                )

                lines.add(
                    "OK unluac ART -> ${output.absolutePath}"
                )

                lines.add(
                    "bytes ${output.length()}"
                )

                lines

            } else {

                output.delete()

                lines.add(
                    "X unluac produced no validated Lua source"
                )

                if (err.isNotBlank()) {
                    lines.add(
                        err.take(800)
                    )
                } else if (text.isNotBlank()) {
                    lines.add(
                        text.take(800)
                    )
                }

                lines
            }

        } catch (t: Throwable) {

            output.delete()

            val msg =
                t.cause?.message
                    ?: t.message
                    ?: t.javaClass.simpleName

            lines.add(
                "X unluac ART: $msg"
            )

            if (
                normalized != input &&
                normalized.isFile
            ) {
                lines.add(
                    "OK normalized bytecode -> " +
                    normalized.absolutePath
                )
            }

            lines
        }
    }
}
