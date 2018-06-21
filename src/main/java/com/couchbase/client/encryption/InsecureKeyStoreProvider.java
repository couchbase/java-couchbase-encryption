/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;

import java.util.HashMap;

/**
 * Insecure key store which stores keys in memory, useful for development testing.
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class InsecureKeyStoreProvider implements KeyStoreProvider {

    private HashMap<String, byte[]> keys = new HashMap<String, byte[]>();
    private String publicKeyName;
    private String privateKeyName;
    private String signingKeyName;

    @Override
    public byte[] getKey(String keyName) {
        return keys.get(keyName);
    }

    @Override
    public void storeKey(String keyName, byte[] secretKey) {
        keys.put(keyName, secretKey);
    }

    @Override
    public String publicKeyName() {
        return this.publicKeyName;
    }

    @Override
    public void publicKeyName(String name) {
        this.publicKeyName = name;
    }

    @Override
    public String privateKeyName() {
        return this.privateKeyName;
    }

    @Override
    public void privateKeyName(String name) {
        this.privateKeyName = name;
    }

    @Override
    public String signingKeyName() {
        return this.signingKeyName;
    }

    @Override
    public void signingKeyName(String name) {
        this.signingKeyName = name;
    }
}