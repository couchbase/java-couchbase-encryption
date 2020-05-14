/*
 * Copyright 2020 Couchbase, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
