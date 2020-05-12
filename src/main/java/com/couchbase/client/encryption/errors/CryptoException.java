/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

public class CryptoException extends RuntimeException {
  public CryptoException() {
  }

  public CryptoException(String message) {
    super(message);
  }

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoException(Throwable cause) {
    super(cause);
  }

  public CryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
