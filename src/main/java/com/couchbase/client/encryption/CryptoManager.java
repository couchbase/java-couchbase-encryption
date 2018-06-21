/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;

import java.util.HashMap;
import java.util.Map;

import com.couchbase.client.encryption.errors.CryptoProviderAliasNullException;
import com.couchbase.client.encryption.errors.CryptoProviderNameNotFoundException;

/**
 * Encryption configuration manager set on the environment for encryption/decryption
 *
 * @author Subhashni Balakrishnan
 * @since 1.0.0
 */
public class CryptoManager {

    private Map<String, CryptoProvider> cryptoProvider;

    /**
     * Creates an instance of Encryption configuration
     */
    public CryptoManager() {
        this.cryptoProvider = new HashMap<String, CryptoProvider>();
    }

    /**
     * Add an encryption algorithm provider
     *
     * @param name an alias name for the encryption provider
     * @param provider Encryption provider implementation
     */
    public void registerProvider(String name, CryptoProvider provider) {
        this.cryptoProvider.put(name, provider);
    }

    /**
     * Get an encryption algorithm provider
     * @param name an alias name for the encryption provider
     *
     * @return encryption crypto provider instance
     */
    public CryptoProvider getProvider(String name) throws Exception {
        if (name == null || name.isEmpty()) {
            throw new CryptoProviderAliasNullException();
        }
        if (!this.cryptoProvider.containsKey(name) || this.cryptoProvider.get(name) == null) {
            throw new CryptoProviderNameNotFoundException();
        }
        return this.cryptoProvider.get(name);
    }
}