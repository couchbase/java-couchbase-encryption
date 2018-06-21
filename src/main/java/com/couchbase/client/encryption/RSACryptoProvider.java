/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.couchbase.client.encryption.errors.CryptoProviderMissingPrivateKeyException;
import com.couchbase.client.encryption.errors.CryptoProviderMissingPublicKeyException;

/**
 * RSA encryption provider
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class RSACryptoProvider implements CryptoProvider {

    private KeyStoreProvider keyStoreProvider;
    private final String CRYPTO_ALG = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    public static final String ALG_NAME = "RSA-2048-OAEP-SHA1";

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
        if (this.keyStoreProvider.publicKeyName() == null) {
            throw new CryptoProviderMissingPublicKeyException();
        }

        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(this.keyStoreProvider.publicKeyName()));
        return cipher.doFinal(data);
    }

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
        if (this.keyStoreProvider.privateKeyName() == null) {
            throw new CryptoProviderMissingPrivateKeyException();
        }

        Cipher cipher = Cipher.getInstance(CRYPTO_ALG);
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(this.keyStoreProvider.privateKeyName()), oaepParams);
        return cipher.doFinal(encrypted);
    }

    public byte[] getSignature(byte[] message) {
        return null;
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        return false;
    }

    private RSAPrivateKey getPrivateKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(this.keyStoreProvider.getKey(keyName));
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    private RSAPublicKey getPublicKey(String keyName) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(this.keyStoreProvider.getKey(keyName));
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    @Override
    public String getProviderName() {
        return ALG_NAME;
    }

    @Override
    public boolean checkAlgorithmNameMatch(String name) {
        return (name.contentEquals(ALG_NAME) || name.contentEquals("RSA-2048"));
    }
}