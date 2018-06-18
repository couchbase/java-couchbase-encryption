/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
 * @since 0.1.0
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