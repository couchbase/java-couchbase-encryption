/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;
import com.couchbase.client.core.deps.io.netty.util.concurrent.DefaultThreadFactory;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Zeroizes (zero-fills) registered byte arrays when closed.
 * <p>
 * The way Java manages memory makes it impossible to guarantee sensitive info
 * is completely wiped from memory, but we can make a best effort.
 */
@Stability.Internal
public class Zeroizer implements Closeable {
  private final List<byte[]> zeroizeMe = new ArrayList<>();

  private static final Jdk8Cleaner cleaner = Jdk8Cleaner.create(
      new DefaultThreadFactory("zeroizer", true));

  private static class ZeriozationTask implements Runnable {
    private final byte[] bytes;

    ZeriozationTask(byte[] bytes) {
      this.bytes = bytes;
    }

    @Override
    public void run() {
      zeroize(bytes);
    }
  }

  /**
   * Schedules zeroization of the byte array to occur when the given referent
   * becomes eligible for garbage collection.
   * <p>
   * Finalizers are deprecated in Java 9. This is a forward-compatible alternative.
   */
  public static void zeroizeWhenUnreachable(Object referent, byte[] bytes) {
    requireNonNull(referent);
    // Don't use a lambda because that would capture a reference to the object
    // and prevent it from becoming unreachable.
    cleaner.register(referent, new ZeriozationTask(bytes));
  }

  /**
   * Fills the given byte array with zeros.
   */
  public static void zeroize(byte[] b) {
    if (b != null) {
      Arrays.fill(b, (byte) 0);
    }
  }

  /**
   * Registers an array to be zeroized when this instance is closed.
   *
   * @return the given array
   */
  public byte[] add(byte[] b) {
    zeroizeMe.add(b);
    return b;
  }

  /**
   * Zero-fills all registered arrays.
   */
  @Override
  public void close() {
    for (byte[] b : zeroizeMe) {
      zeroize(b);
    }
  }
}
