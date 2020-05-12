/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

import com.couchbase.client.core.error.context.ErrorContext;

/**
 * Thrown when the supplied key's size does not match a crypto provider's expected key size.
 */
public class InvalidKeySizeException extends CryptoException {
  public InvalidKeySizeException(String message) {
    super(message);
  }

  public InvalidKeySizeException(String message, ErrorContext ctx) {
    super(message, ctx);
  }

  public InvalidKeySizeException(String message, Throwable cause) {
    super(message, cause);
  }

  public InvalidKeySizeException(String message, Throwable cause, ErrorContext ctx) {
    super(message, cause, ctx);
  }
}
