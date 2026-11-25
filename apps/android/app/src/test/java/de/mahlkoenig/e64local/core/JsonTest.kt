package de.mahlkoenig.e64local.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {

    @Test
    fun `parses the capability envelope with string row values`() {
        val text = """{"data":{"schema":"e64local-api-v1","route":"grind_log",
            "rows":[{"grind_id":"123","grind_weight":"18000"}],"count":1,"limit":20,
            "offset":0,"since":null,"until":null,"hasMore":false},"success":true,"errorCode":0}"""
        val root = Json.parseObject(text)
        assertEquals(true, root.bool("success"))
        val data = root.obj("data")!!
        assertEquals("e64local-api-v1", data.string("schema"))
        val rows = data.toRows()
        assertEquals(1, rows.size)
        assertEquals("123", rows[0].columns["grind_id"])
    }

    @Test
    fun `handles escapes, unicode and nested objects`() {
        val root = Json.parseObject("""{"a":"line\nbreak","b":"\u00e4","c":{"d":[1,2,3],"e":false}}""")
        assertEquals("line\nbreak", root.string("a"))
        assertEquals("ä", root.string("b"))
        assertEquals(3, root.obj("c")!!.array("d")!!.items.size)
        assertEquals(false, root.obj("c")!!.bool("e"))
    }

    @Test
    fun `round trips a request body`() {
        val body = Json.obj(
            "limit" to Json.num(10),
            "since" to Json.str("2026-01-01"),
            "offset" to null,
        )
        assertEquals("""{"limit":10,"since":"2026-01-01"}""", Json.write(body))
    }

    @Test
    fun `rejects malformed input`() {
        runCatching { Json.parse("{not json") }.let { assertTrue(it.isFailure) }
        runCatching { Json.parse("{\"a\":\"unterminated}") }.let { assertTrue(it.isFailure) }
        runCatching { Json.parse("") }.let { assertTrue(it.isFailure) }
    }

    @Test
    fun `missing keys are null rather than exceptions`() {
        val root = Json.parseObject("""{"a":1}""")
        assertNull(root.string("b"))
        assertNull(root.obj("b"))
        assertEquals(null, root.long("a")?.toString()?.let { null } ?: null)
        assertEquals(1L, root.long("a"))
    }

    @Test
    fun `deeply nested device output is rejected instead of overflowing the stack`() {
        val allowed = "[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH)
        assertTrue(Json.parse(allowed) is JsonValue.Arr)

        val tooDeep = "[".repeat(Json.MAX_DEPTH + 1) + "]".repeat(Json.MAX_DEPTH + 1)
        val failure = runCatching { Json.parse(tooDeep) }.exceptionOrNull()
        assertTrue("expected JsonParseException, got $failure", failure is JsonParseException)
    }
}
