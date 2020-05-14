package com.couchbase.client.encryption.internal;

import com.couchbase.client.encryption.Keyring;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Arrays;

import static com.couchbase.client.encryption.internal.Jdk8CleanerTest.collectGarbageAndAssert;

class KeyImplTest {
  @Test
  void keyIsZeroizedWhenUnreachable() throws Exception {
    Keyring.Key key = Keyring.Key.create("foo", new byte[]{1, 2, 3});

    Field f = KeyImpl.class.getDeclaredField("bytes");
    f.setAccessible(true);
    byte[] keyBytes = (byte[]) f.get(key);

    //noinspection UnusedAssignment
    key = null; // so it's immediately eligible for garbage collection

    collectGarbageAndAssert(() -> Arrays.equals(new byte[]{0, 0, 0}, keyBytes));
  }
}
