/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.encryption.errors.InvalidCiphertextException;
import com.couchbase.client.encryption.errors.InvalidCryptoKeyException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

import static com.couchbase.client.encryption.internal.LangHelper.defaultIfNull;

/**
 * Wraps the standard library for the AEAD_AES_256_CBC_HMAC_SHA512 encryption algorithm specified by
 * <a href="https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05">
 * "Authenticated Encryption with AES-CBC and HMAC-SHA"</a>.
 * <p>
 * Here's an informal description of the algorithm.
 * <p>
 * To encrypt:
 * <ol>
 * <li>Split the 64-byte key in half. The first 32 bytes are the HMAC key,
 * and the second 32 bytes are the AES key.
 * <li>Generate a random 16-byte initialization vector (IV) using a cryptographically secure algorithm.
 * <li>Using this IV, encrypt the plaintext with AES in CBC mode with PKCS7 padding.
 * Prepend the IV to the result to get the "AES ciphertext."
 * <li>Calculate an HMAC SHA-512 digest of the following bytes, in order:
 * <ol>
 * <li>The associated data. This is anything you want to have authenticated but not encrypted.
 * It's optional and may have zero length. Note that this data cannot be reconstructed from the
 * output of this method; it must be stored separately.
 * <li>The AES ciphertext.
 * <li>The length <em>in bits</em> of the associated data, represented as an unsigned
 * 64-bit big-endian integer. For example, if there are 42 bytes of associated data,
 * that's 336 bits, or 0x150 in hex. The value to pass to the message digest are these
 * 8 bytes: <code>0x00 0x00 0x00 0x00 0x00 0x00 0x01 0x50</code>.
 * </ol>
 * <li>The digest generated in the previous step should be 64 bytes long.
 * Truncate it to 32 bytes to get the "auth tag" (or signature, if you prefer).
 * <li>Append the auth tag to the AES ciphertext to get the "authenticated ciphertext".
 * Return the authenticated ciphertext.
 * </ol>
 * <p>
 * To decrypt:
 * <ol>
 * <li>Split the key as above.
 * <li>Split the authenticated ciphertext into the AES ciphertext and the auth tag
 * (the auth tag is the last 32 bytes of the authenticated ciphertext).
 * <li>Calculate the HMAC SHA-512 digest as above, then truncate it to 32 bytes.
 * Compare the result to the auth tag using a time-constant comparison (compare every byte;
 * don't short-circuit at the first mismatch).
 * <li>If there's a mismatch, throw an exception or return a special value to signal a failure.
 * Otherwise, proceed to the next step.
 * <li>Decrypt the AES ciphertext (remember, the first 16 bytes are the IV). Return the plaintext.
 * </ol>
 * <p>
 */
public class AeadAes256CbcHmacSha512Cipher {
  private static final int AUTH_TAG_LEN = 32; // bytes
  private static final int IV_LEN = 16; // bytes

  private final SecureRandom secureRandom;
  private final CryptoFactory cryptoFactory;

  /**
   * Create a new cipher using a default SecureRandom and any
   * registered security provider.
   */
  public AeadAes256CbcHmacSha512Cipher() {
    this(null, null);
  }

  /**
   * Create a new cipher using the given SecureRandom and security provider.
   * <p>
   * The security provider must support "HmacSHA512" and "AES/CBC/PKCS5Padding".
   *
   * @param secureRandom (nullable) secure random to use, or null for default.
   * @param securityProvider (nullable) security provider to use, or null to use
   * the most preferred security provider that supports the required algorithms.
   */
  public AeadAes256CbcHmacSha512Cipher(SecureRandom secureRandom, Provider securityProvider) {
    this.cryptoFactory = new CryptoFactory(securityProvider);
    this.secureRandom = defaultIfNull(secureRandom, SecureRandom::new);

    failFastIfMissingAlgorithms();
  }

  private void failFastIfMissingAlgorithms() {
    try {
      newHmacSha512();
      newAesCscPkcs7();
    } catch (Exception e) {
      throw new RuntimeException("Security provider does not support required crypto algorithm.", e);
    }
  }

  public byte[] encrypt(byte[] key, byte[] plaintext, byte[] associatedData) throws Exception {
    checkKeyLength(key);

    try (Zeroizer zeroizer = new Zeroizer()) {
      final byte[] macKey = zeroizer.add(Arrays.copyOfRange(key, 0, 32));
      final byte[] encKey = zeroizer.add(Arrays.copyOfRange(key, 32, 64));

      final byte[] enc = encryptAesCbcPkcs7(encKey, plaintext);
      final byte[] associatedDataLengthInBits = longToBytes(lengthInBits(associatedData));
      final byte[] mac = zeroizer.add(hmacSha512(macKey, associatedData, enc, associatedDataLengthInBits));
      final byte[] authTag = truncate(mac, AUTH_TAG_LEN);

      return concat(enc, authTag);
    }
  }

  public byte[] decrypt(byte[] key, byte[] ciphertext, byte[] associatedData) throws Exception {
    checkKeyLength(key);

    try (Zeroizer zeroizer = new Zeroizer()) {
      final byte[] macKey = zeroizer.add(Arrays.copyOfRange(key, 0, 32));
      final byte[] encKey = zeroizer.add(Arrays.copyOfRange(key, 32, 64));

      final int authTagOffset = ciphertext.length - AUTH_TAG_LEN;
      final byte[] enc = Arrays.copyOfRange(ciphertext, 0, authTagOffset);
      final byte[] authTag = Arrays.copyOfRange(ciphertext, authTagOffset, authTagOffset + AUTH_TAG_LEN);

      final byte[] associatedDataLengthInBits = longToBytes(lengthInBits(associatedData));
      final byte[] computedMac = zeroizer.add(hmacSha512(macKey, associatedData, enc, associatedDataLengthInBits));
      final byte[] computedAuthTag = truncate(computedMac, AUTH_TAG_LEN);

      // time-constant comparison (doesn't bail out at first mismatch)
      if (!MessageDigest.isEqual(authTag, computedAuthTag)) {
        throw new InvalidCiphertextException(
            "Failed to authenticate the ciphertext and associated data.");
      }

      return decryptAesCbcPkcs7(encKey, enc);
    }
  }

  private static void checkKeyLength(byte[] key) {
    if (key.length != 64) {
      throw new InvalidCryptoKeyException("Expected key to be 64 bytes but got " + key.length + " bytes.");
    }
  }

  private byte[] encryptAesCbcPkcs7(byte[] key, byte[] plaintext) throws GeneralSecurityException {
    final byte[] iv = new byte[IV_LEN];
    secureRandom.nextBytes(iv);

    final Cipher cipher = newAesCscPkcs7();
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    try (ZeroizableSecretKey secretKey = new ZeroizableSecretKey(key, "AES")) {
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
      final byte[] ciphertext = cipher.doFinal(plaintext);
      return concat(iv, ciphertext);
    }
  }

  private byte[] decryptAesCbcPkcs7(byte[] key, byte[] ciphertext) throws GeneralSecurityException {
    final Cipher cipher = newAesCscPkcs7();
    final IvParameterSpec iv = new IvParameterSpec(ciphertext, 0, IV_LEN);

    try (ZeroizableSecretKey secretKey = new ZeroizableSecretKey(key, "AES")) {
      cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
      return cipher.doFinal(ciphertext, IV_LEN, ciphertext.length - IV_LEN);
    }
  }

  private byte[] hmacSha512(byte[] key, byte[]... authenticateMe) throws GeneralSecurityException {
    final Mac mac = newHmacSha512();

    try (ZeroizableSecretKey secretKey = new ZeroizableSecretKey(key, "HMAC")) {
      mac.init(secretKey);
      for (byte[] bytes : authenticateMe) {
        mac.update(bytes);
      }
      return mac.doFinal();
    }
  }

  private Cipher newAesCscPkcs7() {
    // Don't be fooled by the name; this is actually PKCS#7 padding.
    // See https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
    return cryptoFactory.newCipher("AES/CBC/PKCS5Padding");
  }

  private Mac newHmacSha512() {
    return cryptoFactory.newMac("HmacSHA512");
  }

  private static long lengthInBits(byte[] bytes) {
    return bytes.length * 8L;
  }

  private static byte[] concat(byte[] first, byte[] second) {
    final byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  private static byte[] truncate(byte[] bytes, int length) {
    return Arrays.copyOfRange(bytes, 0, length);
  }

  private static byte[] longToBytes(long x) {
    return ByteBuffer.allocate(Long.BYTES)
        .putLong(x)
        .array();
  }
}
