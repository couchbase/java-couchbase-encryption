/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.encryption.internal.AeadAes256CbcHmacSha512Cipher;
import com.couchbase.client.encryption.internal.Zeroizer;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Provider for AES-256 in CBC mode authenticated with HMAC SHA-512.
 * <p>
 * Requires a key size of 64 bytes.
 * <p>
 * Create and configure a provider instance using the static
 * {@link #builder()} method.
 * <p>
 * The provider instance is a factory for a {@link Decrypter} and
 * associated {@link Encrypter}s, which can be created by calling
 * {@link #decrypter()} and {@link #encrypterForKey(String)}.
 * <p>
 * The algorithm is formally described in
 * <a href="https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05">
 * Authenticated Encryption with AES-CBC and HMAC-SHA</a>.
 * This is an "old school" authenticated encryption algorithm,
 * selected because it uses well-established cryptographic primitives
 * that are widely available across various platforms.
 * The primitives belong to the set of "Approved Security Functions"
 * for FIPS 140-2.
 */
public class AeadAes256CbcHmacSha512Provider {
  private static final String ALGORITHM = "AEAD_AES_256_CBC_HMAC_SHA512";
  private static final byte[] NO_ASSOCIATED_DATA = new byte[0];

  private final AeadAes256CbcHmacSha512Cipher cipher;
  private final Keyring keyring;

  /**
   * Returns a builder for configuring new provider instances.
   */
  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private Keyring keyring;
    private Optional<SecureRandom> secureRandom = Optional.empty();
    private Optional<Provider> securityProvider = Optional.empty();

    /**
     * Sets the keyring for obtaining data encryption keys.
     * <p>
     * Required.
     */
    public Builder keyring(Keyring keyring) {
      this.keyring = requireNonNull(keyring);
      return this;
    }

    /**
     * Sets the SecureRandom instance for generating Initialization Vectors
     * during encryption.
     * <p>
     * Optional. If not called, defaults to an instance created using
     * the no-arg constructor {@link SecureRandom#SecureRandom()}.
     */
    public Builder secureRandom(SecureRandom secureRandom) {
      this.secureRandom = Optional.ofNullable(secureRandom);
      return this;
    }

    /**
     * Sets the Java Security Provider for obtaining AES and HMAC primitives.
     * <p>
     * Optional. If not called, defaults to the most preferred provider
     * that supports the primitives.
     */
    public Builder securityProvider(Provider provider) {
      this.securityProvider = Optional.of(provider);
      return this;
    }

    public AeadAes256CbcHmacSha512Provider build() {
      if (keyring == null) {
        throw new IllegalStateException("Keyring not set.");
      }
      return new AeadAes256CbcHmacSha512Provider(
          new AeadAes256CbcHmacSha512Cipher(secureRandom.orElse(null), securityProvider.orElse(null)),
          keyring);
    }
  }

  private AeadAes256CbcHmacSha512Provider(AeadAes256CbcHmacSha512Cipher cipher,
                                          Keyring keyring) {
    this.cipher = requireNonNull(cipher);
    this.keyring = requireNonNull(keyring);
  }

  /**
   * Returns a new encrypter that uses the encryption key with the given name.
   */
  public Encrypter encrypterForKey(String keyName) {
    return plaintext -> {
      try (Zeroizer zeroizer = new Zeroizer()) {
        final Keyring.Key key = keyring.getOrThrow(keyName);
        return EncryptionResult.forAlgorithm(ALGORITHM)
            .put("kid", key.id())
            .put("ciphertext", cipher.encrypt(
                zeroizer.add(key.bytes()), plaintext, NO_ASSOCIATED_DATA));
      }
    };
  }

  /**
   * Returns a new decrypter for this algorithm.
   */
  public Decrypter decrypter() {
    return new Decrypter() {
      @Override
      public String algorithm() {
        return ALGORITHM;
      }

      @Override
      public byte[] decrypt(EncryptionResult encrypted) throws Exception {
        try (Zeroizer zeroizer = new Zeroizer()) {
          final Keyring.Key key = keyring.getOrThrow(encrypted.getString("kid"));
          return cipher.decrypt(zeroizer.add(key.bytes()), encrypted.getBytes("ciphertext"), NO_ASSOCIATED_DATA);
        }
      }
    };
  }
}
