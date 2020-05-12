/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.couchbase.client.core.util.CbCollections.mapOf;

/**
 * The encrypted form of a message, consisting of an encryption
 * algorithm name and a set of attributes specific to that algorithm.
 *
 * @apiNote There are no methods for getting/setting attributes of type
 * {@code long} because encryption results are typically serialized as JSON,
 * and JSON numbers with an absolute value larger than 9007199254740991 might
 * not be interpreted correctly by all JSON libraries on all platforms.
 * Please store large numbers as Strings instead.
 */
public class EncryptionResult {
  private final Map<String, Object> map = new HashMap<>();

  private EncryptionResult() {
  }

  /**
   * Creates a new instance associated with the given encryption algorithm name.
   * <p>
   * The algorithm name identifies the {@link Decrypter} that should be used
   * to decrypt this result.
   */
  public static EncryptionResult forAlgorithm(String algorithmName) {
    return EncryptionResult.fromMap(mapOf("alg", algorithmName));
  }

  public String getAlgorithm() {
    return getString("alg");
  }

  public EncryptionResult put(String name, String value) {
    if ("alg".equals(name)) {
      throw new IllegalArgumentException("Attribute name 'alg' is reserved.");
    }
    map.put(name, value);
    return this;
  }

  public EncryptionResult put(String name, int value) {
    map.put(name, value);
    return this;
  }

  public EncryptionResult put(String name, boolean value) {
    map.put(name, value);
    return this;
  }

  public EncryptionResult put(String name, byte[] bytes) {
    return put(name, Base64.getEncoder().encodeToString(bytes));
  }

  public String getString(String name) {
    return (String) map.get(name);
  }

  public Integer getInt(String name) {
    Number number = (Number) map.get(name);
    return number == null ? null : number.intValue();
  }

  public Boolean getBoolean(String name) {
    return (Boolean) map.get(name);
  }

  public byte[] getBytes(String name) {
    String s = getString(name);
    return s == null ? null : Base64.getDecoder().decode(s);
  }

  /**
   * Creates a new instance with attributes from the given map.
   * <p>
   * An {@code Encrypter} should not call this method; instead it should create
   * new instances by calling {@link #forAlgorithm(String)}.
   */
  public static EncryptionResult fromMap(Map<String, Object> map) {
    EncryptionResult r = new EncryptionResult();
    r.map.putAll(map);
    return r;
  }

  public Map<String, Object> asMap() {
    return map;
  }

  @Override
  public String toString() {
    return map.toString();
  }
}
