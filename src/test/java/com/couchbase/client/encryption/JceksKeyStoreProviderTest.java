/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

package com.couchbase.client.encryption;
import org.junit.Assert;
import org.junit.Test;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;
import java.util.Arrays;

public class JceksKeyStoreProviderTest {

    @Test
    public void testSimpleKeyStore() throws Exception {
        JceksKeyStoreProvider provider = new JceksKeyStoreProvider();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGen.init(128, random);
        SecretKey secretKey = keyGen.generateKey();
        String keyName = "testkey";
        provider.storeKey(keyName, secretKey.getEncoded());
        provider.publicKeyName(keyName);
        byte[] secret = provider.getKey(keyName);
        AES128CryptoProvider cryptoProvider = new AES128CryptoProvider(provider);
        String encrypted = DatatypeConverter.printBase64Binary(cryptoProvider.encrypt("test".getBytes()));
        String decrypted = new String(cryptoProvider.decrypt(DatatypeConverter.parseBase64Binary(encrypted)));
        Assert.assertTrue(Arrays.equals(secret, secretKey.getEncoded()));
        Assert.assertEquals(decrypted, "test");
    }
}