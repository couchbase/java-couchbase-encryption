/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * JCEKS key store is a superset of JKS which supports both symmetric and asymmetric keys.
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class JceksKeyStoreProvider implements KeyStoreProvider {

    private final KeyStore ks;
    private String keyPassword;
    private String publicKeyName;
    private String privateKeyName;
    private String signingKeyName;

    public JceksKeyStoreProvider() throws Exception {
        this(null);
    }

    /**
     * Creates an instance of the JCEKS key store provider
     *
     * @param keyPassword password for key protection. Default password is the key name.
     * @throws Exception on failure
     */
    public JceksKeyStoreProvider(String keyPassword) throws Exception {
        this(null, null, keyPassword);
    }

    /**
     * Creates an instance of the JCEKS key store provider
     *
     * @param stream      Input stream to use an existing key store
     * @param password    Password for the key store
     * @param keyPassword password for key protection. Default password is the key name.
     * @throws Exception on failure
     */
    public JceksKeyStoreProvider(InputStream stream, char[] password, String keyPassword) throws Exception {
        this.ks = KeyStore.getInstance("JCEKS");
        this.ks.load(stream, password);
        this.keyPassword = keyPassword;
        //required since 1.8_171 http://www.oracle.com/technetwork/java/javase/8u171-relnotes-4308888.html#JDK-8189997
        System.setProperty("jceks.key.serialFilter", "javax.crypto.spec.SecretKeySpec");
    }

    private KeyStore.PasswordProtection getProtection(String keyName) {
        KeyStore.PasswordProtection protection;
        if (this.keyPassword == null) {
            protection = new KeyStore.PasswordProtection(getHashedString(keyName).toCharArray());
        } else {
            protection = new KeyStore.PasswordProtection(this.keyPassword.toCharArray());
        }
        return protection;
    }

    @Override
    public byte[] getKey(String keyName) throws Exception {
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) this.ks.getEntry(keyName, getProtection(keyName));
        return entry.getSecretKey().getEncoded();
    }

    @Override
    public void storeKey(String keyName, byte[] secretKey) throws Exception {
        SimpleSecretKey secretKeyEntry = new SimpleSecretKey(secretKey);
        this.ks.setEntry(keyName, new KeyStore.SecretKeyEntry(secretKeyEntry), getProtection(keyName));
    }

    @Override
    public String publicKeyName() {
        return this.publicKeyName;
    }

    @Override
    public void publicKeyName(String name) {
        this.publicKeyName = name;
    }

    @Override
    public String privateKeyName() {
        return this.privateKeyName;
    }

    @Override
    public void privateKeyName(String name) {
        this.privateKeyName = name;
    }

    @Override
    public String signingKeyName() {
        return this.signingKeyName;
    }

    @Override
    public void signingKeyName(String name) {
        this.signingKeyName = name;
    }

    private String getHashedString(String keyName) {
        int hash = 7;
        for (int i = 0; i < keyName.length(); i++) {
            hash = hash*31 + keyName.charAt(i);
        }
        return Integer.toString(hash);
    }

    private static class SimpleSecretKey implements SecretKey {
        private final byte[] secret;

        public SimpleSecretKey(byte[] secret) {
            this.secret = secret;
        }

        public String getAlgorithm() {
            return "CUSTOM";
        }

        public String getFormat() {
            return "RAW";
        }

        public byte[] getEncoded() {
            return secret;
        }
    }
}