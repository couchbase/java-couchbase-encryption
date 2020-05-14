/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;
import com.couchbase.client.encryption.Decrypter;
import com.couchbase.client.encryption.EncryptionResult;
import com.couchbase.client.encryption.Keyring;
import com.couchbase.client.encryption.errors.CryptoKeyNotFoundException;
import com.couchbase.client.encryption.errors.InvalidCiphertextException;
import com.couchbase.client.encryption.errors.InvalidKeySizeException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Decrypts messages encrypted by the legacy {@code Aes256CryptoProvider}
 * and {@code Aes128CryptoProvider} classes.
 * <p>
 * Construct new instances with the static factory methods.
 *
 * @see #aes128
 * @see #aes256
 */
@Stability.Internal
public class LegacyAesDecrypter implements Decrypter {
  private final String algorithmName;
  private final int encryptionKeySize;
  private final Keyring keyring;
  private final Function<String, String> encryptionKeyNameToSigningKeyName;

  private LegacyAesDecrypter(String algorithmName, int encryptionKeySize, Keyring keyring, Function<String, String> encryptionKeyNameToSigningKeyName) {
    this.keyring = requireNonNull(keyring);
    this.encryptionKeyNameToSigningKeyName = requireNonNull(encryptionKeyNameToSigningKeyName);
    this.algorithmName = requireNonNull(algorithmName);
    this.encryptionKeySize = encryptionKeySize;
  }

  /**
   * Returns a decryption-only provider for reading fields encrypted by
   * {@code Aes128CryptoProvider} which is now obsolete.
   *
   * @param keyring key ring that holds the encryption and signing keys.
   * @param encryptionKeyNameToSigningKeyName A function that when given the name of
   * an encryption key, returns the name of the associated signing key (or null if unknown).
   * Historically this association was established via the {@code KeyStoreProvider},
   * but that component isn't around anymore.
   */
  public static Decrypter aes128(Keyring keyring, Function<String, String> encryptionKeyNameToSigningKeyName) {
    return new LegacyAesDecrypter("AES-128-HMAC-SHA256", 16, keyring, encryptionKeyNameToSigningKeyName);
  }

  /**
   * Returns a decryption-only provider for reading fields encrypted by
   * {@code Aes256CryptoProvider} which is now obsolete.
   *
   * @param keyring key ring that holds the encryption and signing keys.
   * @param encryptionKeyNameToSigningKeyName A function that when given the name of
   * an encryption key, returns the name of the associated signing key (or null if unknown).
   * Historically this association was established via the {@code KeyStoreProvider},
   * but that component isn't around anymore.
   */
  public static Decrypter aes256(Keyring keyring, Function<String, String> encryptionKeyNameToSigningKeyName) {
    return new LegacyAesDecrypter("AES-256-HMAC-SHA256", 32, keyring, encryptionKeyNameToSigningKeyName);
  }

  /**
   * Returns the encryption key size in bytes.
   */
  private int getKeySize() {
    return encryptionKeySize;
  }

  @Override
  public String algorithm() {
    return algorithmName;
  }

  @Override
  public byte[] decrypt(EncryptionResult encrypted) throws Exception {
    final String alg = encrypted.getAlgorithm();
    final String kid = encrypted.getString("kid");
    final byte[] iv = encrypted.getBytes("iv");
    final byte[] ciphertext = encrypted.getBytes("ciphertext");
    final byte[] sig = encrypted.getBytes("sig");

    final String signMe = kid + alg +
        encrypted.getString("iv") +  // [sic] Yes, the Base64-encoded version.
        encrypted.getString("ciphertext"); // [sic] Yes, the Base64-encoded version.

    final byte[] calculatedSignature = sign(getSigningKeyName(kid),
        signMe.getBytes(Charset.defaultCharset())); // [sic] Yes, the default charset.

    if (!MessageDigest.isEqual(sig, calculatedSignature)) {
      throw new InvalidCiphertextException("Signature does not match.");
    }

    try (ZeroizableSecretKey key = getAesKey(kid)) {
      final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
      return cipher.doFinal(ciphertext);
    }
  }

  private ZeroizableSecretKey getKey(String keyId, String algorithm) {
    try (Zeroizer zeroizer = new Zeroizer()) {
      final byte[] keyBytes = zeroizer.add(keyring.getOrThrow(keyId).bytes());
      return new ZeroizableSecretKey(keyBytes, algorithm);
    }
  }

  private ZeroizableSecretKey getAesKey(String keyName) {
    final ZeroizableSecretKey key = getKey(keyName, "AES");

    final int actualSize = key.size();
    if (actualSize != getKeySize()) {
      key.destroy();
      throw new InvalidKeySizeException(
          algorithm() + " requires key with " + getKeySize() + " bytes but key '" + keyName + "' has " + actualSize + " bytes.");
    }
    return key;
  }

  private String getSigningKeyName(String encryptionKeyName) {
    return Optional.of(encryptionKeyNameToSigningKeyName.apply(encryptionKeyName))
        .orElseThrow(() -> new CryptoKeyNotFoundException("No mapping to signature key name found for encryption key '" + encryptionKeyName + "'"));
  }

  private byte[] sign(String signingKeyName, byte[]... signMe) throws Exception {
    try (ZeroizableSecretKey key = getKey(signingKeyName, "HMAC")) {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(key);
      for (byte[] array : signMe) {
        mac.update(array);
      }
      return mac.doFinal();
    }
  }
}
