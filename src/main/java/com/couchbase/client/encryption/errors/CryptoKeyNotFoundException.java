/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

/**
 * Thrown when a message cannot be encrypted or decrypted because a required key is missing.
 */
public class CryptoKeyNotFoundException extends CryptoException {
  public CryptoKeyNotFoundException() {
  }

  public CryptoKeyNotFoundException(String message) {
    super(message);
  }

  public CryptoKeyNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoKeyNotFoundException(Throwable cause) {
    super(cause);
  }

  public CryptoKeyNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
