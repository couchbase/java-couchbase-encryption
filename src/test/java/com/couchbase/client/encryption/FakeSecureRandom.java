/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;

class FakeSecureRandom extends SecureRandom {
  private final byte[] fixedBytes;

  public FakeSecureRandom(byte[] bytes) {
    this.fixedBytes = requireNonNull(bytes);
  }

  @Override
  public void nextBytes(byte[] output) {
    if (output.length != fixedBytes.length) {
      throw new IllegalArgumentException("expected output array to have length " + fixedBytes.length);
    }
    System.arraycopy(fixedBytes, 0, output, 0, fixedBytes.length);
  }
}
