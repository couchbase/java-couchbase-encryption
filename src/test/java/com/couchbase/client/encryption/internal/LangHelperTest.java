package com.couchbase.client.encryption.internal;

import org.junit.jupiter.api.Test;

import static com.couchbase.client.encryption.internal.LangHelper.substringBetween;
import static org.junit.jupiter.api.Assertions.*;

class LangHelperTest {

  @Test
  void substringBetweenBehavesLikeApacheCommonsLang() {
    assertEquals("b", substringBetween("wx[b]yz", "[", "]"));

    assertNull(substringBetween(null, "a", "a"));
    assertNull(substringBetween("a", null, "a"));
    assertNull(substringBetween("a", "a", null));

    assertEquals("", substringBetween("", "", ""));
    assertNull(substringBetween("", "", "]"));
    assertNull(substringBetween("", "[", ""));
    assertNull(substringBetween("", "[", "]"));

    assertEquals("", substringBetween("a", "", ""));
    assertEquals("", substringBetween("ab", "", ""));
    assertEquals("", substringBetween("ab", "a", ""));
    assertEquals("a", substringBetween("[a]", "[", "]"));
    assertEquals("ab", substringBetween("[ab]", "[", "]"));
    assertEquals("", substringBetween("[]", "[", "]"));
    assertEquals("abc", substringBetween("yabcz", "y", "z"));
    assertEquals("abc", substringBetween("yabczyabcz", "y", "z"));
  }
}
