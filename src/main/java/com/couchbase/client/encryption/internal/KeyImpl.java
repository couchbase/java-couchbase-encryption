/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

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
