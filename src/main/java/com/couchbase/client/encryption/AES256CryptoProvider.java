/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;

/**
 * AES encryption provider using 256 bit keys
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class AES256CryptoProvider extends AESCryptoProviderBase {

    public static final String ALG_NAME = "AES-256-HMAC-SHA256";
    private int KEY_SIZE = 32;

    /**
     * Create an instance of the crypto algorithm provider
     *
     * @param provider Key store provider
     */
    public AES256CryptoProvider(KeyStoreProvider provider) {
        this.keyStoreProvider = provider;
    }

    protected int getKeySize() {
        return KEY_SIZE;
    }

    @Override
    public String getProviderName() { return ALG_NAME; }

    @Override
    public boolean checkAlgorithmNameMatch(String name) {
        return (name.contentEquals(ALG_NAME) || name.contentEquals("AES-256"));
    }
}