package com.couchbase.client.encryption.internal;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static com.couchbase.client.encryption.internal.Jdk8CleanerTest.collectGarbageAndAssert;
import static com.couchbase.client.encryption.internal.Zeroizer.zeroizeWhenUnreachable;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class ZeroizerTest {
  @Test
  void zeroizeFillsWithZeroes() {
    byte[] b = new byte[]{1, 2, 3};
    Zeroizer.zeroize(b);
    assertArrayEquals(new byte[]{0, 0, 0}, b);
  }

  @Test
  void registeredArraysAreZeroedWhenZeroizerCloses() {
    byte[] a = new byte[]{1, 2, 3};
    byte[] b = new byte[]{4, 5, 6};

    try (Zeroizer zeroizer = new Zeroizer()) {
      byte[] a1 = zeroizer.add(a);
      byte[] b1 = zeroizer.add(b);

      assertSame(a, a1);
      assertSame(b, b1);

      assertArrayEquals(new byte[]{1, 2, 3}, a);
      assertArrayEquals(new byte[]{4, 5, 6}, b);
    }

    assertArrayEquals(new byte[]{0, 0, 0}, a);
    assertArrayEquals(new byte[]{0, 0, 0}, b);
  }

  @Test
  void arraysIsZeroedWhenReferentIsGarbageCollected() {
    byte[] a = new byte[]{1, 2, 3};

    Object referent = new Object();
    zeroizeWhenUnreachable(referent, a);

    // shouldn't get zeroized yet since we're still holding on to the referent
    assertArrayEquals(new byte[]{1, 2, 3}, a);

    //noinspection UnusedAssignment
    referent = null; // Now! Zeroize now!

    collectGarbageAndAssert(() -> Arrays.equals(new byte[]{0, 0, 0}, a));
  }
}
