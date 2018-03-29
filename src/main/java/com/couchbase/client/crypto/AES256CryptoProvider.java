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

package com.couchbase.client.crypto;

/**
 * AES encryption provider using 256 bit keys
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class AES256CryptoProvider extends AESCryptoProviderBase {

    public static final String NAME = "AES-256-HMAC-SHA256";

    /**
     * Create an instance of the crypto algorithm provider with the same key used
     * for encryption and HMAC signature calculation.
     *
     * @param provider Key store provider
     * @param keyName Key used for encryption and HMAC signature
     */
    public AES256CryptoProvider(KeyStoreProvider provider, String keyName) {
        this(provider, keyName, keyName);
    }

    /**
     * Create an instance of the crypto algorithm provider with different keys
     * for encryption and HMAC signature calculation.(Recommended)
     *
     * @param keyStoreProvider Key store provider
     * @param keyName Encryption key
     * @param hmacKeyName HMAC key
     */
    public AES256CryptoProvider(KeyStoreProvider keyStoreProvider, String keyName, String hmacKeyName) {
        this.keySize = 32;
        this.keyStoreProvider = keyStoreProvider;
        this.keyName = keyName;
        this.hmacKeyName = hmacKeyName;
    }

    /**
     * Crypto algorithm and HMAC
     *
     * @return Crypto provider name
     */
    @Override
    public String getProviderName() { return NAME; }

}