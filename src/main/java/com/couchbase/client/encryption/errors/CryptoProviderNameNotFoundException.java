/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption.errors;

/**
 * CryptoProviderNameNotFoundException is thrown when the provider name is
 * not registered on the Crypto manager.
 *
 * @author Subhashni Balakrishnan
 * @since 1.0.0
 */
public class CryptoProviderNameNotFoundException extends Exception {

    public CryptoProviderNameNotFoundException() {
        super();
    }

    public CryptoProviderNameNotFoundException(String message) {
        super(message);
    }

    public CryptoProviderNameNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoProviderNameNotFoundException(Throwable cause) {
        super(cause);
    }
}
