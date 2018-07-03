/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption.errors;

/**
 * CryptoProviderNoPublicKeyException is thrown when the public key is
 * not set on the Crypto provider.
 *
 * @author Subhashni Balakrishnan
 * @since 1.0.0
 */
public class CryptoProviderNoPublicKeyException extends Exception {

    public CryptoProviderNoPublicKeyException() {
        super();
    }

    public CryptoProviderNoPublicKeyException(String message) {
        super(message);
    }

    public CryptoProviderNoPublicKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoProviderNoPublicKeyException(Throwable cause) {
        super(cause);
    }
}
