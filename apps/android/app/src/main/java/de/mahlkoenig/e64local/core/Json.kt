package de.mahlkoenig.e64local.core

/**
 * A small, dependency-free JSON reader and writer.
 *
 * The Local Owner API only needs flat objects, arrays of string maps and the
 * occasional nested config object, so a hand-written parser keeps the app free
 * of third-party libraries and makes the request/response logic testable on a
 * plain JVM. Numbers stay strings unless [asLong] is called, mirroring the
 * server contract where DB values are strings.
 */
sealed interface JsonValue {
    data class Obj(val entries: LinkedHashMap<String, JsonValue>) : JsonValue {
        operator fun get(key: String): JsonValue? = entries[key]
        fun string(key: String): String? = (entries[key] as? Str)?.value
        fun obj(key: String): Obj? = entries[key] as? Obj
        fun array(key: String): Arr? = entries[key] as? Arr
        fun bool(key: String): Boolean? = (entries[key] as? Bool)?.value
        fun long(key: String): Long? = (entries[key] as? Num)?.literal?.toLongOrNull()
        fun double(key: String): Double? = (entries[key] as? Num)?.literal?.toDoubleOrNull()
        fun has(key: String): Boolean = entries.containsKey(key)
    }

    data class Arr(val items: List<JsonValue>) : JsonValue

    data class Str(val value: String) : JsonValue

    data class Num(val literal: String) : JsonValue {
        fun toLongOrNull(): Long? = literal.toLongOrNull()
        fun toDoubleOrNull(): Double? = literal.toDoubleOrNull()
    }

    data class Bool(val value: Boolean) : JsonValue

    data object Null : JsonValue
}

class JsonParseException(message: String) : Exception(message)

object Json {
    /** Deepest object/array nesting accepted from a device response. */
    const val MAX_DEPTH = 64

    fun parse(text: String): JsonValue {
        val parser = Parser(text)
        val value = parser.parseValue()
        parser.skipWhitespace()
        if (!parser.atEnd()) {
            throw JsonParseException("trailing data at offset ${parser.offset}")
        }
        return value
    }

    fun parseObject(text: String): JsonValue.Obj =
        parse(text) as? JsonValue.Obj ?: throw JsonParseException("expected a JSON object")

    fun write(value: JsonValue): String = StringBuilder().also { writeTo(value, it) }.toString()

    fun obj(vararg pairs: Pair<String, JsonValue?>): JsonValue.Obj {
        val map = LinkedHashMap<String, JsonValue>()
        for ((key, value) in pairs) {
            if (value != null) map[key] = value
        }
        return JsonValue.Obj(map)
    }

    fun str(value: String): JsonValue = JsonValue.Str(value)

    fun num(value: Long): JsonValue = JsonValue.Num(value.toString())

    fun bool(value: Boolean): JsonValue = JsonValue.Bool(value)

    private fun writeTo(value: JsonValue, out: StringBuilder) {
        when (value) {
            is JsonValue.Obj -> {
                out.append('{')
                var first = true
                for ((key, child) in value.entries) {
                    if (!first) out.append(',')
                    first = false
                    writeString(key, out)
                    out.append(':')
                    writeTo(child, out)
                }
                out.append('}')
            }

            is JsonValue.Arr -> {
                out.append('[')
                value.items.forEachIndexed { index, child ->
                    if (index > 0) out.append(',')
                    writeTo(child, out)
                }
                out.append(']')
            }

            is JsonValue.Str -> writeString(value.value, out)
            is JsonValue.Num -> out.append(if (value.literal.isBlank()) "0" else value.literal)
            is JsonValue.Bool -> out.append(if (value.value) "true" else "false")
            JsonValue.Null -> out.append("null")
        }
    }

    private fun writeString(value: String, out: StringBuilder) {
        out.append('"')
        for (char in value) {
            when (char) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                else -> if (char < ' ') out.append("\\u%04x".format(char.code)) else out.append(char)
            }
        }
        out.append('"')
    }

    private class Parser(private val text: String) {
        var offset = 0
            private set

        /** Guards against a device-supplied document that would blow the stack. */
        private var depth = 0

        fun atEnd(): Boolean = offset >= text.length

        private fun enter() {
            depth++
            if (depth > MAX_DEPTH) {
                throw JsonParseException("nesting deeper than $MAX_DEPTH levels at offset $offset")
            }
        }

        fun skipWhitespace() {
            while (offset < text.length && text[offset].isWhitespace()) offset++
        }

        fun parseValue(): JsonValue {
            skipWhitespace()
            if (atEnd()) throw JsonParseException("unexpected end of input")
            return when (val char = text[offset]) {
                '{' -> parseObjectValue()
                '[' -> parseArrayValue()
                '"' -> JsonValue.Str(parseString())
                't' -> literal("true", JsonValue.Bool(true))
                'f' -> literal("false", JsonValue.Bool(false))
                'n' -> literal("null", JsonValue.Null)
                else -> if (char == '-' || char.isDigit()) parseNumber() else {
                    throw JsonParseException("unexpected character '$char' at offset $offset")
                }
            }
        }

        private fun parseObjectValue(): JsonValue.Obj {
            enter()
            try {
                expect('{')
                val map = LinkedHashMap<String, JsonValue>()
                skipWhitespace()
                if (peek() == '}') {
                    offset++
                    return JsonValue.Obj(map)
                }
                while (true) {
                    skipWhitespace()
                    if (peek() != '"') throw JsonParseException("expected an object key at offset $offset")
                    val key = parseString()
                    skipWhitespace()
                    expect(':')
                    map[key] = parseValue()
                    skipWhitespace()
                    when (peek()) {
                        ',' -> offset++
                        '}' -> {
                            offset++
                            return JsonValue.Obj(map)
                        }

                        else -> throw JsonParseException("expected ',' or '}' at offset $offset")
                    }
                }
            } finally {
                depth--
            }
        }

        private fun parseArrayValue(): JsonValue.Arr {
            enter()
            try {
                expect('[')
                val items = ArrayList<JsonValue>()
                skipWhitespace()
                if (peek() == ']') {
                    offset++
                    return JsonValue.Arr(items)
                }
                while (true) {
                    items += parseValue()
                    skipWhitespace()
                    when (peek()) {
                        ',' -> offset++
                        ']' -> {
                            offset++
                            return JsonValue.Arr(items)
                        }

                        else -> throw JsonParseException("expected ',' or ']' at offset $offset")
                    }
                }
            } finally {
                depth--
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (true) {
                if (atEnd()) throw JsonParseException("unterminated string")
                when (val char = text[offset++]) {
                    '"' -> return out.toString()
                    '\\' -> {
                        if (atEnd()) throw JsonParseException("unterminated escape")
                        when (val escaped = text[offset++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                if (offset + 4 > text.length) {
                                    throw JsonParseException("truncated \\u escape")
                                }
                                val hex = text.substring(offset, offset + 4)
                                val code = hex.toIntOrNull(16)
                                    ?: throw JsonParseException("invalid \\u escape: $hex")
                                out.append(code.toChar())
                                offset += 4
                            }

                            else -> throw JsonParseException("invalid escape '\\$escaped'")
                        }
                    }

                    else -> out.append(char)
                }
            }
        }

        private fun parseNumber(): JsonValue.Num {
            val start = offset
            if (peek() == '-') offset++
            while (!atEnd() && text[offset].isDigit()) offset++
            if (peek() == '.') {
                offset++
                while (!atEnd() && text[offset].isDigit()) offset++
            }
            if (peek() == 'e' || peek() == 'E') {
                offset++
                if (peek() == '+' || peek() == '-') offset++
                while (!atEnd() && text[offset].isDigit()) offset++
            }
            val literal = text.substring(start, offset)
            if (literal == "-" || literal.isEmpty()) {
                throw JsonParseException("invalid number at offset $start")
            }
            return JsonValue.Num(literal)
        }

        private fun literal(word: String, value: JsonValue): JsonValue {
            if (!text.startsWith(word, offset)) {
                throw JsonParseException("expected '$word' at offset $offset")
            }
            offset += word.length
            return value
        }

        private fun expect(char: Char) {
            skipWhitespace()
            if (peek() != char) throw JsonParseException("expected '$char' at offset $offset")
            offset++
        }

        private fun peek(): Char? = if (atEnd()) null else text[offset]
    }
}
