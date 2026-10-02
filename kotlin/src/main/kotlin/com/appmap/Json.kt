package com.appmap

/**
 * A tiny, dependency-free JSON writer. Handles the value shapes AppMap builds
 * (String, Boolean, Number, List, Map, null) and pretty-prints with two spaces.
 */
object Json {
    fun write(value: Any?, indent: Int = 2): String {
        val sb = StringBuilder()
        writeValue(sb, value, indent, 0)
        return sb.toString()
    }

    private fun writeValue(sb: StringBuilder, value: Any?, indent: Int, level: Int) {
        when (value) {
            null -> sb.append("null")
            is String -> writeString(sb, value)
            is Boolean -> sb.append(value.toString())
            is Int, is Long, is Short, is Byte -> sb.append(value.toString())
            is Double -> sb.append(number(value))
            is Float -> sb.append(number(value.toDouble()))
            is Number -> sb.append(value.toString())
            is Map<*, *> -> writeObject(sb, value, indent, level)
            is Iterable<*> -> writeArray(sb, value.toList(), indent, level)
            is Array<*> -> writeArray(sb, value.toList(), indent, level)
            else -> writeString(sb, value.toString())
        }
    }

    private fun number(d: Double): String =
        if (d.isNaN() || d.isInfinite()) "null"
        else if (d == Math.floor(d) && Math.abs(d) < 1e15) d.toLong().toString()
        else d.toString()

    private fun writeObject(sb: StringBuilder, map: Map<*, *>, indent: Int, level: Int) {
        if (map.isEmpty()) { sb.append("{}"); return }
        sb.append("{\n")
        val entries = map.entries.toList()
        entries.forEachIndexed { i, e ->
            pad(sb, indent, level + 1)
            writeString(sb, e.key.toString())
            sb.append(": ")
            writeValue(sb, e.value, indent, level + 1)
            if (i < entries.size - 1) sb.append(",")
            sb.append("\n")
        }
        pad(sb, indent, level)
        sb.append("}")
    }

    private fun writeArray(sb: StringBuilder, list: List<*>, indent: Int, level: Int) {
        if (list.isEmpty()) { sb.append("[]"); return }
        sb.append("[\n")
        list.forEachIndexed { i, v ->
            pad(sb, indent, level + 1)
            writeValue(sb, v, indent, level + 1)
            if (i < list.size - 1) sb.append(",")
            sb.append("\n")
        }
        pad(sb, indent, level)
        sb.append("]")
    }

    private fun pad(sb: StringBuilder, indent: Int, level: Int) {
        if (indent > 0) sb.append(" ".repeat(indent * level))
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }
}
