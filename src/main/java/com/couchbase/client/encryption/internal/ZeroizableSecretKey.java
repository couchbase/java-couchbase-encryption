/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;

import javax.crypto.SecretKey;
import java.io.Closeable;

import static com.couchbase.client.encryption.internal.Zeroizer.zeroize;
import static java.util.Objects.requireNonNull;

/**
 * Cousin of SecretKeySpec whose {@link #destroy()} method fills the
 * encoded form of the key with zeros (instead of throwing DestroyFailedException).
 */
@Stability.Internal
public class ZeroizableSecretKey implements SecretKey, Closeable {
  private final byte[] bytes;
  private final String algorithm;
  private boolean destroyed;

  /**
   * Clones the byte array. Caller is responsible for zeroizing the given byte array.
   */
  public ZeroizableSecretKey(byte[] bytes, String algorithm) {
    this.bytes = bytes.clone();
    this.algorithm = requireNonNull(algorithm);
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public synchronized byte[] getEncoded() {
    if (destroyed) {
      throw new IllegalStateException("Key has been destroyed.");
    }
    return bytes.clone();
  }

  public synchronized void destroy() {
    destroyed = true;
    zeroize(bytes);
  }

  public int size() {
    return bytes.length;
  }

  public synchronized boolean isDestroyed() {
    return destroyed;
  }

  @Override
  public void close() {
    destroy();
  }
}
