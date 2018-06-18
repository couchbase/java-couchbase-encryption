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

import com.couchbase.client.encryption.utils.Base64;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.nio.charset.Charset;

/**
 * Uses hashicorp vault key store to store secrets/keys
 *
 * @author Subhashni Balakrishnan
 * @since 0.1.0
 */
public class HashicorpVaultKeyStoreProvider implements KeyStoreProvider {

    private final String endpoint;
    private final String mount;
    private final String token;
    private ObjectMapper mapper = new ObjectMapper();
    private String publicKeyName;
    private String privateKeyName;
    private String signingKeyName;

    /**
     * Creates an instance of vault key provider
     *
     * @param endpoint Server endpoint
     * @param token Client token for authentication
     */
    public HashicorpVaultKeyStoreProvider(String endpoint, String token) {
        this(endpoint, "secret", token);
    }

    /**
     * Creates an instance of vault key provider
     *
     * @param endpoint Server endpoint
     * @param mount Mount point on vault
     * @param token Client token for authentication
     */
    public HashicorpVaultKeyStoreProvider(String endpoint, String mount, String token) {
        this.endpoint = "http://" + endpoint;
        this.mount = mount;
        this.token = token;
    }

    public byte[] getKey(String keyName) throws Exception {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet get = new HttpGet(this.endpoint + "/v1/" + this.mount + "/" + keyName);
        get.addHeader("X-Vault-Token", this.token);

        CloseableHttpResponse response = client.execute(get);
        if (response.getStatusLine().getStatusCode() != 200) {
            throw new Exception("Store key failed on vault " + response.getStatusLine().toString());
        }
        String storedVal = EntityUtils.toString(response.getEntity(), Charset.forName("UTF-8"));
        JsonNode obj = mapper.readTree(storedVal);
        client.close();
        return Base64.decode(obj.get("data").get("value").toString().replace("\"",""));
    }

    public void storeKey(String keyName, byte[] key) throws Exception {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpPost post = new HttpPost(this.endpoint + "/v1/" + this.mount + "/" + keyName);
        post.addHeader("X-Vault-Token",this.token);
        ObjectNode node = mapper.createObjectNode();
        node.put("value" , Base64.encode(key));
        post.setEntity(new StringEntity(node.toString(), ContentType.APPLICATION_JSON));
        CloseableHttpResponse response = client.execute(post);
        if (response.getStatusLine().getStatusCode() != 200 && response.getStatusLine().getStatusCode() != 204) {
            throw new Exception("Store key failed on vault " + response.getStatusLine().toString());
        }
        client.close();
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