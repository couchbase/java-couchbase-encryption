/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

/**
 * Knows how to encrypt a message.
 */
public interface Encrypter {
  /**
   * Encrypts the given message.
   * <p>
   * The encryption result specifies the algorithm of the decrypter to use
   * when reading this encrypted field. The result also includes any attributes
   * required for decryption, such as the name of the secret key or other
   * parameters specific to the algorithm.
   *
   * @param plaintext the bytes to encrypt
   */
  EncryptionResult encrypt(byte[] plaintext) throws Exception;
}
