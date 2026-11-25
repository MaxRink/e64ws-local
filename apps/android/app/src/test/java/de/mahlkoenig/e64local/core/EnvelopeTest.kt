package de.mahlkoenig.e64local.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnvelopeTest {

    private val success = """{"data":{"schema":"e64local-api-v1","route":"capabilities",
        "apiVersion":"1","routes":["capabilities"],"success":true},"success":true,"errorCode":0}"""

    private val failure = """{"error":"owner token required",
        "console":"Local API requires owner token in /db/e64local/token",
        "success":false,"errorCode":401}"""

    @Test
    fun `success envelope carries a data object`() {
        val result = Envelope.parse(success, 200)
        assertTrue(result is ApiResult.Success)
        val envelope: JsonValue.Obj = (result as ApiResult.Success).data
        assertEquals("capabilities", envelope.obj("data")!!.string("route"))
    }

    @Test
    fun `handled failure is reported from the body not the HTTP status`() {
        // The vendor dispatcher always answers HTTP 400 for handled failures.
        val result = Envelope.parse(failure, 400)
        assertTrue(result is ApiResult.Failure)
        val failureResult = result as ApiResult.Failure
        assertEquals(401, failureResult.errorCode)
        assertTrue(failureResult.isTokenProblem)
        assertFalse(failureResult.isDevGateProblem)
    }

    @Test
    fun `dev gate refusal is a 403 errorCode`() {
        val result = Envelope.parse("""{"error":"dev mode required","success":false,"errorCode":403}""", 403)
        assertEquals(403, (result as ApiResult.Failure).errorCode)
        assertTrue(result.isDevGateProblem)
    }

    @Test
    fun `HTML error page is reported as a failure and never parsed as data`() {
        val result = Envelope.parse("<html><body>Login</body></html>", 200)
        assertTrue(result is ApiResult.Failure)
        assertTrue((result as ApiResult.Failure).message.contains("HTML"))
    }

    @Test
    fun `empty body is a failure`() {
        assertTrue(Envelope.parse("", 400) is ApiResult.Failure)
        assertTrue(Envelope.parse(null, 500) is ApiResult.Failure)
    }

    @Test
    fun `missing data object is a failure`() {
        val result = Envelope.parse("""{"success":true,"errorCode":0}""", 200)
        val data = (result as ApiResult.Success).data
        assertTrue(Envelope.dataOf(data) is ApiResult.Failure)
    }

    @Test
    fun `toleration of the unserialised empty settings object`() {
        // PHP's json_encode of an empty assoc array gives [] rather than {}.
        val text = """{"data":{"route":"settings","settings":[],"redacted":[],"count":0},
            "success":true,"errorCode":0}"""
        val result = Envelope.parse(text, 200)
        assertTrue(result is ApiResult.Success)
    }
}
