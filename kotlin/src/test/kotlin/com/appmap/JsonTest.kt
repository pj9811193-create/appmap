package com.appmap

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonTest {
    @Test fun writesString() {
        assertEquals("\"hi\"", Json.write("hi"))
    }

    @Test fun escapesSpecialCharacters() {
        assertEquals("\"a\\\"b\"", Json.write("a\"b"))
        assertEquals("\"line\\nbreak\"", Json.write("line\nbreak"))
        assertEquals("\"tab\\there\"", Json.write("tab\there"))
    }

    @Test fun writesBooleansAndNull() {
        assertEquals("true", Json.write(true))
        assertEquals("null", Json.write(null))
    }

    @Test fun writesIntegersWithoutDecimal() {
        assertEquals("42", Json.write(42))
        assertEquals("42", Json.write(42.0))
        assertEquals("156.5", Json.write(156.5))
    }

    @Test fun writesEmptyContainers() {
        assertEquals("[]", Json.write(emptyList<Any>()))
        assertEquals("{}", Json.write(emptyMap<String, Any>()))
    }

    @Test fun writesNestedMap() {
        val out = Json.write(linkedMapOf("a" to 1, "b" to listOf("x", "y")))
        assertTrue(out.contains("\"a\": 1"))
        assertTrue(out.contains("\"x\""))
        assertTrue(out.contains("\"y\""))
    }
}
