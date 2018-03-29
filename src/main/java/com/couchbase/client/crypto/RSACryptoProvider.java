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
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA encryption provider
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class RSACryptoProvider implements CryptoProvider {

    private KeyStoreProvider keyStoreProvider;
    private String keyName;
    private final String SIGNATURE_ALG = "SHA256withRSA";
    private final String CRYPTO_ALG = "RSA";
    public static final String NAME = "RSA-2048";

    /**
     * Create an instance of the RSA Cryto pro
     *
     * @param keyName the keyName for the public, private pair
     */
    public RSACryptoProvider(String keyName) {
        this.keyName = keyName;
    }

    /**
     * Get the key store provider set for the crypto provider use.
     *
     * @return Key store provider set
     */
    public KeyStoreProvider getKeyStoreProvider() {
        return this.keyStoreProvider;
    }

    public void setKeyStoreProvider(KeyStoreProvider provider) {
        this.keyStoreProvider = provider;
    }

    /**
     * Get the encryption key pair name used
     *
     * @return Key name
     */
    public String getKeyName() {
        return this.keyName;
    }

    /**
     * Set the encryption key pair to be used
     *
     * @param keyName Key name
     */
    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

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
        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(keyName));
        return cipher.doFinal(data);
    }


    /**
     * Get the initialization vector size
     *
     * @return iv size
     */
    public int getIVSize() {
        return 0;
    }

    /**
     * Decrypts the given data. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encrypted Encrypted data
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encrypted) throws Exception {
        return decrypt(encrypted, this.keyName);
    }

    /**
     * Decrypts the given data using the key given. Will throw exceptions
     * if the key store and key name are not set.
     *
     * @param encrypted Encrypted data
     * @param keyName Encryption/Decryption key name
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encrypted, String keyName) throws Exception {
        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(keyName));
        return cipher.doFinal(encrypted);
    }

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @return signature
     */
    public byte[] getSignature(byte[] message) throws Exception {
        return getSignature(message, this.keyName);
    }

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param keyName The key to be used
     * @return signature
     */
    public byte[] getSignature(byte[] message, String keyName) throws Exception {
        Signature signatureAlg = Signature.getInstance(SIGNATURE_ALG);
        signatureAlg.initSign(getPrivateKey(keyName));
        return signatureAlg.sign();
    }

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @return signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) throws Exception {
        return verifySignature(message, signature, this.keyName);
    }

    /**
     * verify the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @param signature Signature used for message
     * @param keyName The key to be used
     * @return signature
     */
    public boolean verifySignature(byte[] message, byte[] signature, String keyName) throws Exception {
        Signature signatureAlg = Signature.getInstance(SIGNATURE_ALG);
        signatureAlg.initVerify(getPublicKey(keyName));
        return signatureAlg.verify(signature);
    }

    private RSAPrivateKey getPrivateKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALG);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(this.keyStoreProvider.getKey(keyName + "_private"));
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    private RSAPublicKey getPublicKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALG);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(this.keyStoreProvider.getKey(keyName + "_public"));
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    public String getProviderName() {
        return NAME;
    }
}