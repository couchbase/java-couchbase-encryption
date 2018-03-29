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
 * CryptoProvider interface for cryptographic algorithm provider implementations.
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public interface CryptoProvider {

    /**
     * Get the key store provider set for the crypto provider use.
     *
     * @return Key store provider set
     */
    KeyStoreProvider getKeyStoreProvider();

    /**
     * Set the key store provider for the crypto provider to get keys from.
     *
     * @param provider Key store provider
     */
    void setKeyStoreProvider(KeyStoreProvider provider);

    /**
     * Get the default key name used by the provider
     *
     * @return
     */
    String getKeyName();

    /**
     * Set the default key name to be used by the provider
     */
    void setKeyName(String keyName);

    /**
     * Encrypts the given data using key given. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param data Data to be encrypted
     * @return Encrypted bytes
     */
    byte[] encrypt(byte[] data, String keyName) throws Exception;

    /**
     * Encrypts the given data. Will throw exceptions if the key store and
     * key name are not set.
     *
     * @param data Data to be encrypted
     * @return Encrypted bytes
     */
    byte[] encrypt(byte[] data) throws Exception;

    /**
     * Get the initialization vector size that prepended to the encrypted bytes
     *
     * @return iv size
     */
    int getIVSize();

    /**
     * Decrypts the given data using the key given. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encrypted Encrypted data
     * @return Decrypted bytes
     */
    byte[] decrypt(byte[] encrypted, String keyName) throws Exception;

    /**
     * Decrypts the given data. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encrypted Encrypted data
     * @return Decrypted bytes
     */
    byte[] decrypt(byte[] encrypted) throws Exception;

    /**
     * Get the signature for the integrity check using the key given.
     *
     * @param message The message to check for correctness
     * @return signature
     */
    byte[] getSignature(byte[] message, String keyName) throws Exception;

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @return signature
     */
    byte[] getSignature(byte[] message) throws Exception;

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @return signature
     */
    boolean verifySignature(byte[] message, byte[] signature) throws Exception;

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @param keyName HMAC key name
     * @return signature
     */
    boolean verifySignature(byte[] message, byte[] signature, String keyName) throws Exception;

    /**
     * Get the crypto provider name.
     *
     * @return name
     */
     String getProviderName();
}