package com.appmap

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TargetTest {
    @Test fun parsesBareHost() {
        val t = Target.parse("example.com")
        assertEquals("example.com", t.hostname)
        assertEquals("https://example.com", t.url)
        assertEquals("https", t.scheme)
    }

    @Test fun parsesHttpsUrl() {
        val t = Target.parse("https://example.com/path?q=1")
        assertEquals("example.com", t.hostname)
        assertEquals("https", t.scheme)
    }

    @Test fun parsesHttpScheme() {
        assertEquals("http", Target.parse("http://example.com").scheme)
    }

    @Test fun stripsPortAndUserInfo() {
        assertEquals("example.com", Target.parse("http://user@example.com:8080/x").hostname)
    }

    @Test fun trimsWhitespaceAndTrailingDot() {
        assertEquals("example.com", Target.parse("  example.com.  ").hostname)
    }

    @Test fun acceptsIpv4() {
        assertEquals("127.0.0.1", Target.parse("127.0.0.1").hostname)
    }

    @Test fun rejectsEmpty() {
        assertFailsWith<InputError> { Target.parse("") }
        assertFailsWith<InputError> { Target.parse("   ") }
    }

    @Test fun rejectsWhitespaceInside() {
        assertFailsWith<InputError> { Target.parse("exa mple.com") }
    }

    @Test fun rejectsUnsupportedScheme() {
        assertFailsWith<InputError> { Target.parse("ftp://example.com") }
    }

    @Test fun rejectsBadHostnames() {
        assertFailsWith<InputError> { Target.parse("-bad.example.com") }
        assertFailsWith<InputError> { Target.parse("example..com") }
        assertFailsWith<InputError> { Target.parse("a".repeat(300) + ".com") }
        assertFailsWith<InputError> { Target.parse("256.1.1.1") }
    }
}
