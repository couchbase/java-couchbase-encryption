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
 * Key provider interface for key store implementation.
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public interface KeyStoreProvider {

    /**
     * Internally used by crypto providers to retrieve the key for encryption/decryption.
     *
     * @param keyName The key to be retrieved for secret keys. Add suffix _public/_private to retrieve
     *                public/private key
     * @return key Key as raw bytes
     * @throws Exception on failure
     */
    byte[] getKey(String keyName) throws Exception;

    /**
     * Add a key
     *
     * @param keyName Name of the key
     * @param key Secret key as byes
     * @throws Exception on failure
     */
    void storeKey(String keyName, byte[] key) throws Exception;

    /**
     * Get the name of the encryption key
     *
     * @return encryption key name
     */
    String publicKeyName();

    /**
     * Set the name of the encryption key
     *
     * @param name encryption key
     */
    void publicKeyName(String name);

    /**
     * Get the private key name set
     *
     * @return private key name
     */
    String privateKeyName();

    /**
     * Set the private key name required for an asymmetic cryptographic algorithm
     *
     * @param name
     */
    void privateKeyName(String name);

    /**
     * Get the signing key name/password set
     *
     * @return name
     */
    String signingKeyName();

    /**
     * Set signing key name/password
     *
     * @param name Signing key name
     */
    void signingKeyName(String name);
}