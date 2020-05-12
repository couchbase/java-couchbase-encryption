/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

/**
 * Knows how to decrypt messages.
 */
public interface Decrypter {
  /**
   * Returns the name of the encryption algorithm this decrypter uses.
   */
  String algorithm();

  /**
   * Decrypts the given message.
   */
  byte[] decrypt(EncryptionResult encrypted) throws Exception;
}
