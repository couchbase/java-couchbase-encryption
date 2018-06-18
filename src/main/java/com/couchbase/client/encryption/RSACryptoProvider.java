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
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.couchbase.client.encryption.errors.CryptoProviderMissingPrivateKeyException;
import com.couchbase.client.encryption.errors.CryptoProviderMissingPublicKeyException;
import com.couchbase.client.encryption.errors.CryptoProviderMissingSigningKeyException;

/**
 * RSA encryption provider
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class RSACryptoProvider implements CryptoProvider {

    private KeyStoreProvider keyStoreProvider;
    private final String SIGNATURE_ALG = "SHA256withRSA";
    private final String CRYPTO_ALG = "RSA";
    public static final String ALG = "RSA-2048";

    /**
     * Create an instance of the RSA Cryto provider
     *
     * @param provider Keystore provider for the public and private key
     */
    public RSACryptoProvider(KeyStoreProvider provider) {
        this.keyStoreProvider = provider;
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
     * Encrypts the given data using the key set.
     *
     * @param data Data to be encrypted
     * @return Encrypted bytes
     */
    public byte[] encrypt(byte[] data) throws Exception {
        if (this.keyStoreProvider.privateKeyName() == null) {
            throw new CryptoProviderMissingPrivateKeyException();
        }

        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(this.keyStoreProvider.privateKeyName()));
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
     * Decrypts the given data using the key given.
     *
     * @param encrypted Encrypted data
     * @return Decrypted bytes
     */
    public byte[] decrypt(byte[] encrypted) throws Exception {
        if (this.keyStoreProvider.publicKeyName() == null) {
            throw new CryptoProviderMissingPublicKeyException();
        }

        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(this.keyStoreProvider.publicKeyName()));
        return cipher.doFinal(encrypted);
    }

    /**
     * Get the signature for the integrity check.
     *
     * @param message The message to check for correctness
     * @return signature
     */
    public byte[] getSignature(byte[] message) throws Exception {
        if (this.keyStoreProvider.signingKeyName() == null) {
            throw new CryptoProviderMissingSigningKeyException();
        }

        Signature signatureAlg = Signature.getInstance(SIGNATURE_ALG);
        signatureAlg.initSign(getPrivateKey(this.keyStoreProvider.signingKeyName()));
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
        if (this.keyStoreProvider.signingKeyName() == null) {
            throw new CryptoProviderMissingSigningKeyException();
        }

        Signature signatureAlg = Signature.getInstance(SIGNATURE_ALG);
        signatureAlg.initVerify(getPublicKey(this.keyStoreProvider.signingKeyName()));
        return signatureAlg.verify(signature);
    }

    private RSAPrivateKey getPrivateKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALG);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(this.keyStoreProvider.getKey(keyName));
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    private RSAPublicKey getPublicKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALG);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(this.keyStoreProvider.getKey(keyName));
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    @Override
    public String getProviderAlgorithmName() {
        return ALG;
    }
}