/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

/**
 * Thrown when the supplied key's size does not match a crypto provider's expected key size.
 */
public class InvalidKeySizeException extends CryptoException {

  public InvalidKeySizeException() {
    super();
  }

  public InvalidKeySizeException(String message) {
    super(message);
  }

  public InvalidKeySizeException(String message, Throwable cause) {
    super(message, cause);
  }

  public InvalidKeySizeException(Throwable cause) {
    super(cause);
  }
}
