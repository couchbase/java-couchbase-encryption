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
import com.couchbase.client.encryption.Keyring;

import static com.couchbase.client.encryption.internal.Zeroizer.zeroizeWhenUnreachable;
import static java.util.Objects.requireNonNull;

/**
 * The standard key implementation.
 * <p>
 * Zeroizes itself prior to being garbage collected.
 *
 * @implNote This class makes defensive copies of the byte array in order
 * to guarantee immutability, which is important since keys may be cached.
 */
@Stability.Internal
public class KeyImpl implements Keyring.Key {
  private final String id;
  private final byte[] bytes;

  public KeyImpl(String id, byte[] bytes) {
    this.id = requireNonNull(id);
    this.bytes = bytes.clone();
    zeroizeWhenUnreachable(this, this.bytes);
  }

  public String id() {
    return id;
  }

  public byte[] bytes() {
    return bytes.clone();
  }

  @Override
  public String toString() {
    return "Key{" +
        "id='" + id + '\'' +
        ", length=" + bytes.length +
        '}';
  }
}
