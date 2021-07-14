/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import com.couchbase.client.java.json.JsonObject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import static com.couchbase.client.core.util.CbCollections.mapOf;

public class EncryptionBenchmark {

  private static final String ENCRYPTED_FIELD_NAME = "secret";

  @State(Scope.Benchmark)
  public static class CryptoState {

    @Param({
        "32",
        "512",
        "4096",
    })
    public int fieldSizeInBytes;

    public final CryptoManager cryptoManager;

    @Setup
    public void setup() {
      valueBytes = stringOfLength(fieldSizeInBytes);

      objWithEncryptedField = JsonObject.create()
          .crypto(cryptoManager)
          .put(ENCRYPTED_FIELD_NAME, valueBytes)
          .object();
    }

    public String valueBytes;
    public JsonObject objWithEncryptedField;

    public CryptoState() {
      Keyring keyring = Keyring.fromMap(mapOf("test-key", testKeyBytes()));

      AeadAes256CbcHmacSha512Provider provider = AeadAes256CbcHmacSha512Provider.builder()
          .keyring(keyring)
          .build();

      this.cryptoManager = DefaultCryptoManager.builder()
          .decrypter(provider.decrypter())
          .defaultEncrypter(provider.encrypterForKey("test-key"))
          .build();
    }

    private static String stringOfLength(int len) {
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < len; i++) {
        sb.append("x");
      }
      return sb.toString();
    }

    private static byte[] testKeyBytes() {
      byte[] keyBytes = new byte[64];
      for (int i = 0; i < keyBytes.length; i++) {
        keyBytes[i] = (byte) i;
      }
      return keyBytes;
    }
  }

  @Benchmark
  public JsonObject encrypt(CryptoState state) {
    JsonObject obj = JsonObject.create();
    obj.crypto(state.cryptoManager)
        .put(ENCRYPTED_FIELD_NAME, state.valueBytes);
    return obj;
  }

  @Benchmark
  public String decrypt(CryptoState state) {
    return state.objWithEncryptedField
        .crypto(state.cryptoManager)
        .getString(ENCRYPTED_FIELD_NAME);
  }

}
