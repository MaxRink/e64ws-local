package de.mahlkoenig.e64local.core

/**
 * Request bodies for the three log routes. `limit`, `offset`, `since` and
 * `until` are the only accepted parameters; values are clamped client-side to
 * the documented ranges so an accidental value cannot turn into a 400.
 */
data class LogQuery(
    val limit: Int? = null,
    val offset: Int = 0,
    val since: String? = null,
    val until: String? = null,
) {
    init {
        require(offset >= 0) { "offset must not be negative" }
    }

    /** Clamped to the documented bounds before the body is built. */
    val effectiveLimit: Int? get() = limit?.coerceIn(1, MAX_ROWS)

    val effectiveOffset: Int get() = offset.coerceIn(0, MAX_OFFSET)

    fun toBody(): JsonValue.Obj = Json.obj(
        "limit" to effectiveLimit?.let { Json.num(it.toLong()) },
        "offset" to if (effectiveOffset > 0) Json.num(effectiveOffset.toLong()) else null,
        "since" to normalized(since)?.let { Json.str(it) },
        "until" to normalized(until)?.let { Json.str(it) },
    )

    fun toJson(): String = Json.write(toBody())

    fun nextPage(pageSize: Int): LogQuery =
        copy(offset = (effectiveOffset + pageSize).coerceAtMost(MAX_OFFSET))

    fun previousPage(pageSize: Int): LogQuery =
        copy(offset = (effectiveOffset - pageSize).coerceAtLeast(0))

    companion object {
        const val MAX_ROWS = 5000
        const val MAX_OFFSET = 1_000_000

        /**
         * Accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, the `T` form and Unix
         * seconds. Anything else is dropped rather than sent, so a typo cannot
         * produce a server-side 400.
         */
        fun normalized(value: String?): String? {
            val text = value?.trim().orEmpty()
            if (text.isEmpty()) return null
            if (Regex("^[0-9]{1,10}$").matches(text)) return text
            val date = Regex("^(\\d{4})-(\\d{2})-(\\d{2})$")
            val dateTime = Regex("^(\\d{4})-(\\d{2})-(\\d{2})[ T](\\d{2}):(\\d{2}):(\\d{2})$")
            val dateMatch = date.matchEntire(text)
            if (dateMatch != null) {
                val (year, month, day) = dateMatch.destructured
                return text.takeIf { isCalendarDate(year.toInt(), month.toInt(), day.toInt()) }
            }
            val dateTimeMatch = dateTime.matchEntire(text) ?: return null
            val (year, month, day, hour, minute, second) = dateTimeMatch.destructured
            val valid = isCalendarDate(year.toInt(), month.toInt(), day.toInt()) &&
                hour.toInt() in 0..23 && minute.toInt() in 0..59 && second.toInt() in 0..59
            return if (valid) text.replace('T', ' ') else null
        }

        private fun isCalendarDate(year: Int, month: Int, day: Int): Boolean {
            if (year !in 1970..2100 || month !in 1..12 || day < 1) return false
            val leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
            val daysInMonth = when (month) {
                2 -> if (leap) 29 else 28
                4, 6, 9, 11 -> 30
                else -> 31
            }
            return day <= daysInMonth
        }

        fun isValid(value: String?): Boolean = value.isNullOrBlank() || normalized(value) != null
    }
}

/** A page of log rows as returned by one route. */
data class LogPage(
    val route: String,
    val rows: List<StringRow>,
    val count: Int,
    val limit: Int,
    val offset: Int,
    val since: String?,
    val until: String?,
    val hasMore: Boolean,
    val note: String? = null,
) {
    val nextOffset: Int get() = offset + count

    companion object {
        fun from(data: JsonValue.Obj): LogPage {
            val rows = data.toRows()
            val limit = data.long("limit")?.toInt() ?: 0
            val offset = data.long("offset")?.toInt() ?: 0
            return LogPage(
                route = data.string("route") ?: "",
                rows = rows,
                count = data.long("count")?.toInt() ?: rows.size,
                limit = limit,
                offset = offset,
                since = data.string("since"),
                until = data.string("until"),
                hasMore = data.bool("hasMore") ?: (rows.size == limit && limit > 0),
                note = data.string("note"),
            )
        }
    }
}
