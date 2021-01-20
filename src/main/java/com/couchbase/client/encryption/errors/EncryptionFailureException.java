/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

/**
 * Thrown when the {@link com.couchbase.client.core.encryption.CryptoManager}
 * is unable to encrypt a plaintext.
 * <p>
 * The cause of this exception should pinpoint the reason for the failure.
 */
public class EncryptionFailureException extends CryptoException {
  public EncryptionFailureException(String message) {
    super(message);
  }

  public EncryptionFailureException(String message, Throwable cause) {
    super(message, cause);
  }
}
