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

import java.util.HashMap;

/**
 * Insecure key store which stores keys in memory, useful for development testing.
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class InsecureKeyStoreProvider implements KeyStoreProvider {

    private HashMap<String, byte[]> keys = new HashMap<String, byte[]>();
    private String publicKeyName;
    private String privateKeyName;
    private String signingKeyName;

    @Override
    public byte[] getKey(String keyName) {
        return keys.get(keyName);
    }

    @Override
    public void storeKey(String keyName, byte[] secretKey) {
        keys.put(keyName, secretKey);
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
}