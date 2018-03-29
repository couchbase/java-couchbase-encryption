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

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Base class for AES crypto provider
 *
 * @author Subhashni Balakrishnan
 */
public abstract class AESCryptoProviderBase implements CryptoProvider {

    protected KeyStoreProvider keyStoreProvider;
    protected String keyName;
    protected String hmacKeyName;
    protected int keySize;
    private final int IV_SIZE = 16;

    /**
     * Get the key store provider used
     *
     * @return Key store provider
     */
    public KeyStoreProvider getKeyStoreProvider() {
        return this.keyStoreProvider;
    }

    /**
     * Set the key store provider to be used
     *
     * @param provider Key store provider
     */
    public void setKeyStoreProvider(KeyStoreProvider provider) {
        this.keyStoreProvider = provider;
    }

    /**
     * Get the encryption key name used
     *
     * @return Key name
     */
    public String getKeyName() {
        return this.keyName;
    }

    /**
     * Set the encryption key to be used
     *
     * @param keyName Key name
     */
    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    /**
     * Get HMAC key used for generating signature to verify data integrity
     *
     * @return HMAC key name
     */
    public String getHMACKeyName() {return this.hmacKeyName; }

    /**
     * Set HMAC key to be used for generating signature to verify data integrity
     *
     * @param hmacKeyName HMAC key name
     */
    public void setHMACKeyName(String hmacKeyName) { this.hmacKeyName = hmacKeyName; }

    /**
     * Encrypts the given data using the key set. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param data Data to be encrypted
     * @return Encrypted bytes
     */
    public byte[] encrypt(byte[] data) throws Exception {
        return encrypt(data, this.keyName);
    }

    /**
     * Encrypts the given data using the key set. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param data Data to be encrypted
     * @param keyName Encryption key name
     * @return Encrypted bytes
     */
    public byte[] encrypt(byte[] data, String keyName) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(keyName), "AES");
        checkKeySize(key);

        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

        byte[] encrypted = cipher.doFinal(data);
        byte[] encryptedWithIv = new byte[encrypted.length + IV_SIZE];
        System.arraycopy(iv, 0, encryptedWithIv, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, encryptedWithIv, IV_SIZE, encrypted.length);
        return encryptedWithIv;
    }

    /**
     * Get the initialization vector size
     *
     * @return iv size
     */
    public int getIVSize() {
        return IV_SIZE;
    }

    /**
     * Decrypts the given data. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encryptedwithIv Encrypted data with IV
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encryptedwithIv) throws Exception {
        return decrypt(encryptedwithIv, this.keyName);
    }

    /**
     * Decrypts the given data using the key given. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encryptedwithIv Encrypted data
     * @param keyName Encryption/Decryption key name
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encryptedwithIv, String keyName) throws Exception {
        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(keyName), "AES");
        checkKeySize(key);
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedwithIv, 0, iv, 0, ivSize);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        int encryptedSize = encryptedwithIv.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedwithIv, ivSize, encryptedBytes, 0, encryptedSize);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(encryptedBytes);
    }

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @return signature
     */
    public byte[] getSignature(byte[] message) throws Exception {
        return getSignature(message, this.hmacKeyName);
    }

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param hmacKeyName The HMAC key to be used
     * @return signature
     */
    public byte[] getSignature(byte[] message, String hmacKeyName) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(hmacKeyName), "HMAC");
        m.init(key);
        return m.doFinal(message);
    }

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @return signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) throws Exception {
        return verifySignature(message, signature, this.hmacKeyName);
    }

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @param hmacKeyName HMAC key name
     * @return signature
     */
    public boolean verifySignature(byte[] message, byte[] signature, String hmacKeyName) throws Exception {
        return Arrays.equals(getSignature(message, hmacKeyName), signature);
    }

    public abstract String getProviderName();

    private void checkKeySize(SecretKeySpec key) throws Exception {
        int keySize = key.getEncoded().length;
        if (keySize != this.keySize) {
            throw new Exception("Invalid key size " + keySize + " for "+ this.getProviderName() +" Algorithm");
        }
    }
}