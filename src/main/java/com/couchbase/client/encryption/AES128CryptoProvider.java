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

/**
 * AES encryption provider using 128 bit keys
 *
 * @author Subhashni Balakrishan
 * @since 0.1.0
 */
public class AES128CryptoProvider extends AESCryptoProviderBase {

    public static final String ALG_NAME = "AES-128-CBC-HMAC-SHA256";

    /**
     * Create an instance of the crypto algorithm provider.
     *
     * @param keyStoreProvider Key store provider
     */
    public AES128CryptoProvider(KeyStoreProvider keyStoreProvider) {
        this.keyStoreProvider = keyStoreProvider;
    }

    protected int getKeySize() {
        return 16;
    }

    @Override
    public String getProviderAlgorithmName() { return ALG_NAME; }

}