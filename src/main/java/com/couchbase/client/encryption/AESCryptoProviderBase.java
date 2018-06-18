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

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

import com.couchbase.client.encryption.errors.CryptoProviderKeySizeException;
import com.couchbase.client.encryption.errors.CryptoProviderMissingPublicKeyException;
import com.couchbase.client.encryption.errors.CryptoProviderMissingSigningKeyException;

/**
 * Base class for AES crypto provider
 *
 * @author Subhashni Balakrishnan
 */
public abstract class AESCryptoProviderBase implements CryptoProvider {

    protected KeyStoreProvider keyStoreProvider;
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
     * Encrypts the given data using the key set. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param data Data to be encrypted
     * @return Encrypted bytes
     */
    public byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        if (this.keyStoreProvider.publicKeyName() == null) {
            throw new CryptoProviderMissingPublicKeyException();
        }

        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(this.keyStoreProvider.publicKeyName()), "AES");
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
     * Decrypts the given data using the key given. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encryptedwithIv Encrypted data
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encryptedwithIv) throws Exception {
        if (this.keyStoreProvider.publicKeyName() == null) {
            throw new CryptoProviderMissingPublicKeyException();
        }

        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(this.keyStoreProvider.publicKeyName()), "AES");
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
    @Override
    public byte[] getSignature(byte[] message) throws Exception {
        if (this.keyStoreProvider.signingKeyName() == null) {
            throw new CryptoProviderMissingSigningKeyException();
        }

        Mac m = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = new SecretKeySpec(this.keyStoreProvider.getKey(this.keyStoreProvider.signingKeyName()), "HMAC");
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
        return Arrays.equals(getSignature(message), signature);
    }

    public abstract String getProviderAlgorithmName();

    protected abstract int getKeySize();

    private void checkKeySize(SecretKeySpec key) throws Exception {
        int keySize = key.getEncoded().length;
        if (keySize != getKeySize()) {
            throw new CryptoProviderKeySizeException("Invalid key size " + keySize + " for "+ this.getProviderAlgorithmName() +" Algorithm");
        }
    }
}