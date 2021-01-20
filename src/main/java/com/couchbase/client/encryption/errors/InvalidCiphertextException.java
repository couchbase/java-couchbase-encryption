/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

public class InvalidCiphertextException extends CryptoException {
  public InvalidCiphertextException(String message) {
    super(message);
  }

  public InvalidCiphertextException(String message, Throwable cause) {
    super(message, cause);
  }
}
