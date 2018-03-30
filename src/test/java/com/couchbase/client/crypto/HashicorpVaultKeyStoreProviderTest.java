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

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;

@Ignore("Requires hashicorp vault to be setup")
public class HashicorpVaultKeyStoreProviderTest {

    @Test
    public void testSimpleKeyStore() throws Exception {
        HashicorpVaultKeyStoreProvider provider = new HashicorpVaultKeyStoreProvider("127.0.0.1:8200", "9767eb5d-3faa-f055-b58e-f86a8e376f94");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGen.init(128, random);
        SecretKey secretKey = keyGen.generateKey();
        String keyName = "testkey";
        provider.storeKey(keyName, secretKey.getEncoded());
        byte[] storedKey = provider.getKey(keyName);
        Assert.assertTrue(Arrays.equals(secretKey.getEncoded(), storedKey));
    }
}
