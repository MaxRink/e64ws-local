package de.mahlkoenig.e64local.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LogQueryTest {

    @Test
    fun `default body is an empty object`() {
        assertEquals("{}", LogQuery().toJson())
    }

    @Test
    fun `limit, offset and filters are serialised`() {
        val query = LogQuery(limit = 500, offset = 1000, since = "2026-01-01", until = "2026-01-31 23:59:59")
        assertEquals(
            """{"limit":500,"offset":1000,"since":"2026-01-01","until":"2026-01-31 23:59:59"}""",
            query.toJson(),
        )
    }

    @Test
    fun `limit is clamped to the documented range`() {
        assertEquals(5000, LogQuery(limit = 999_999).effectiveLimit)
        assertEquals(1, LogQuery(limit = 0).effectiveLimit)
        assertEquals(1, LogQuery(limit = -5).effectiveLimit)
        assertEquals(null, LogQuery(limit = null).effectiveLimit)
    }

    @Test
    fun `offset is clamped and never negative`() {
        assertEquals(0, LogQuery(offset = 0).effectiveOffset)
        assertEquals(1_000_000, LogQuery(offset = 5_000_000).effectiveOffset)
        // A negative offset is rejected at construction, never sent.
        assertTrue(runCatching { LogQuery(offset = -1) }.isFailure)
    }

    @Test
    fun `paging math follows offset plus count`() {
        val page = LogQuery(limit = 100, offset = 200)
        assertEquals(300, page.nextPage(100).offset)
        assertEquals(100, page.previousPage(100).offset)
        assertEquals(0, LogQuery(offset = 0).previousPage(100).offset)
    }

    @Test
    fun `time filters accept every documented form`() {
        assertEquals("2026-01-01", LogQuery.normalized("2026-01-01"))
        assertEquals("2026-01-01 12:00:00", LogQuery.normalized("2026-01-01 12:00:00"))
        assertEquals("2026-01-01 12:00:00", LogQuery.normalized("2026-01-01T12:00:00"))
        assertEquals("1767225600", LogQuery.normalized("1767225600"))
        assertEquals(null, LogQuery.normalized(""))
        assertEquals(null, LogQuery.normalized("  "))
        assertEquals(null, LogQuery.normalized(null))
    }

    @Test
    fun `time filters reject nonsense so a typo is never sent`() {
        listOf("yesterday", "2026-13-01", "2026-01-01 25:00:00", "01/01/2026", "2026-1-1").forEach {
            assertEquals(it, null, LogQuery.normalized(it))
            assertFalse(it, LogQuery.isValid(it))
        }
        assertTrue(LogQuery.isValid("2026-01-01"))
        assertTrue(LogQuery.isValid(""))
    }

    @Test
    fun `log page parses rows and the paging hint`() {
        val data = Json.parseObject(
            """{"route":"grind_log","rows":[{"grind_id":"2"},{"grind_id":"1"}],
                "count":2,"limit":2,"offset":0,"since":null,"until":null,"hasMore":true}""",
        )
        val page = LogPage.from(data)
        assertEquals(2, page.rows.size)
        assertEquals("grind_log", page.route)
        assertEquals(2, page.nextOffset)
        assertTrue(page.hasMore)
    }

    @Test
    fun `alert log note is surfaced`() {
        val data = Json.parseObject(
            """{"route":"alert_log","rows":[],"count":0,"limit":500,"offset":0,
                "hasMore":false,"note":"alert_log table not present on this firmware"}""",
        )
        val page = LogPage.from(data)
        assertTrue(page.note!!.contains("not present"))
        assertEquals(0, page.nextOffset)
    }

    @Test
    fun `queries with different pages are not equal`() {
        assertNotEquals(LogQuery(offset = 0), LogQuery(offset = 20))
    }
}
