package com.couchbase.client.encryption.internal;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZeroizableSecretKeyTest {
  @Test
  void keyIsZeroizedOnDestruction() throws Exception {
    ZeroizableSecretKey key = new ZeroizableSecretKey(new byte[]{1, 2, 3}, "FOO");
    assertArrayEquals(new byte[]{1, 2, 3}, key.getEncoded());

    key.destroy();

    Field f = ZeroizableSecretKey.class.getDeclaredField("bytes");
    f.setAccessible(true);
    byte[] bytes = (byte[]) f.get(key);
    assertArrayEquals(new byte[]{0, 0, 0}, bytes);
  }

  @Test
  void cannotGetBytesFromDestroyedKey() throws Exception {
    ZeroizableSecretKey key = new ZeroizableSecretKey(new byte[]{1, 2, 3}, "FOO");
    assertFalse(key.isDestroyed());

    key.destroy();

    assertTrue(key.isDestroyed());
    assertThrows(IllegalStateException.class, key::getEncoded);
  }

  @Test
  void keyIsDestroyedOnClose() throws Exception {
    ZeroizableSecretKey key = new ZeroizableSecretKey(new byte[]{1, 2, 3}, "FOO");
    key.close();
    assertTrue(key.isDestroyed());
  }
}
