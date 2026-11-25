package de.mahlkoenig.e64local.core

/** The server's two response shapes: success with `data`, or a failure code. */
sealed interface ApiResult<out T> {
    data class Success<T>(val data: T) : ApiResult<T>

    /**
     * A handled failure. The vendor dispatcher sends HTTP 400 for every handled
     * failure, so [httpStatus] is not the discriminator: [errorCode] is.
     *
     * [retryAfter] is the top-level `retryAfter` field the module adds to a
     * rate-limit refusal (`errorCode 429`). It is kept as data, not folded into
     * [message], so a caller can show a countdown instead of parsing prose.
     */
    data class Failure(
        val errorCode: Int,
        val message: String,
        val console: String? = null,
        val httpStatus: Int = 400,
        val retryAfter: Int? = null,
    ) : ApiResult<Nothing> {
        val isTokenProblem: Boolean get() = errorCode == 401
        val isDevGateProblem: Boolean get() = errorCode == 403
        val isRateLimited: Boolean get() = errorCode == 429

        /** A single line suitable for the UI; never includes a token. */
        fun describe(): String = buildString {
            append("HTTP ").append(httpStatus)
            append(" / errorCode ").append(errorCode)
            append(": ").append(message)
            if (!console.isNullOrBlank()) append(" — ").append(console)
        }
    }
}

class ApiException(message: String, cause: Throwable? = null) : Exception(message, cause)

object Envelope {
    const val SCHEMA = "e64local-api-v1"

    /**
     * Parses the common envelope. `null` bodies and HTML error pages are
     * reported as failures rather than thrown, because the vendor dispatcher
     * can answer with a login page when the session has expired.
     */
    fun parse(body: String?, httpStatus: Int): ApiResult<JsonValue.Obj> {
        if (body.isNullOrBlank()) {
            return ApiResult.Failure(
                errorCode = if (httpStatus in 400..499) httpStatus else 500,
                message = "empty response from device",
                httpStatus = httpStatus,
            )
        }
        val root = try {
            Json.parseObject(body)
        } catch (exc: JsonParseException) {
            val hint = if (body.trimStart().startsWith("<")) {
                "the device returned HTML instead of JSON (the session may have expired)"
            } else {
                "the device did not return JSON"
            }
            return ApiResult.Failure(
                errorCode = if (httpStatus in 400..499) httpStatus else 500,
                message = "$hint: ${exc.message}",
                httpStatus = httpStatus,
            )
        }

        val success = root.bool("success") ?: false
        if (!success) {
            return ApiResult.Failure(
                errorCode = root.long("errorCode")?.toInt() ?: httpStatus.coerceAtLeast(400),
                message = root.string("error") ?: "request failed",
                console = root.string("console"),
                httpStatus = httpStatus,
                // The module writes the rate-limit delay next to the envelope,
                // not inside `data`: action_prepare and action_execute both do.
                retryAfter = root.long("retryAfter")?.toInt()?.coerceAtLeast(0),
            )
        }
        return ApiResult.Success(root)
    }

    /** Returns `data`, failing when the payload is not an object. */
    fun dataOf(envelope: JsonValue.Obj): ApiResult<JsonValue.Obj> {
        val data = envelope.obj("data")
            ?: return ApiResult.Failure(500, "response is missing the data object")
        return ApiResult.Success(data)
    }
}

/** One row of a log/table route; every column value is a string. */
data class StringRow(val columns: Map<String, String>)

fun JsonValue.Obj.toRows(): List<StringRow> {
    val array = array("rows") ?: return emptyList()
    return array.items.mapNotNull { item ->
        val obj = item as? JsonValue.Obj ?: return@mapNotNull null
        val columns = LinkedHashMap<String, String>()
        for ((key, value) in obj.entries) {
            columns[key] = when (value) {
                is JsonValue.Str -> value.value
                is JsonValue.Num -> value.literal
                is JsonValue.Bool -> value.value.toString()
                is JsonValue.Null -> ""
                else -> Json.write(value)
            }
        }
        StringRow(columns)
    }
}
