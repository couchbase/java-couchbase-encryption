/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.java.Bucket;
import com.couchbase.client.java.Cluster;
import com.couchbase.client.java.Collection;
import com.couchbase.client.java.env.ClusterEnvironment;
import com.couchbase.client.java.json.JsonObject;
import com.couchbase.client.java.json.JsonObjectCrypto;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.couchbase.BucketDefinition;
import org.testcontainers.couchbase.CouchbaseContainer;
import org.testcontainers.couchbase.CouchbaseService;
import org.testcontainers.utility.DockerImageName;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;

import static com.couchbase.client.core.util.CbCollections.mapOf;
import static com.couchbase.client.java.ClusterOptions.clusterOptions;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntegrationTest {

  private static final DockerImageName COUCHBASE_IMAGE_NAME =
      DockerImageName.parse("couchbase/server").withTag("6.5.1");

  private static CouchbaseContainer couchbase;

  private static final String BUCKET_NAME = "default";
  private static final String TEST_KEY_NAME = "my-key";
  private static final String KEYSTORE_INTEGRITY_PASSWORD = "integrity";
  private static final Function<String, String> KEYSTORE_PROTECTION_PASSWORD =
      keyName -> keyName + "-protection";

  @BeforeAll
  static void startCouchbase() {
    couchbase = new CouchbaseContainer(COUCHBASE_IMAGE_NAME)
        .withEnabledServices(CouchbaseService.KV) // only need KV
        .withBucket(new BucketDefinition(BUCKET_NAME));
    couchbase.start();
  }

  @AfterAll
  static void stopCouchbase() {
    couchbase.stop();
  }

  private ClusterEnvironment env;
  private Cluster cluster;
  private Collection collection;

  @AfterEach
  void cleanup() {
    try {
      cluster.disconnect();
      env.shutdown();
    } finally {
      // prevent accidental reuse between tests
      cluster = null;
      env = null;
      collection = null;
    }
  }

  /**
   * An example test method that shows how to set up the
   * Couchbase client.
   */
  @Test
  void template() throws Exception {
    standardInitWith(standardCryptoManager(simpleKeyring()));

    // At this point, the "collection" field has been initialized,
    // so we can use it to read and write documents with encrypted fields.

    JsonObject obj = JsonObject.create();
    JsonObjectCrypto crypto = obj.crypto(collection);
    crypto.put("magicWord", "xyzzy");

    collection.upsert("foo", obj);
    obj = collection.get("foo").contentAsObject();

    assertNotEquals(obj.get("magicWord"), "xyzzy");
    assertTrue(obj.get("encrypted$magicWord") instanceof JsonObject);

    String decryptedValue = obj.crypto(collection).getString("magicWord");
    assertEquals(decryptedValue, "xyzzy");
  }

  private AeadAes256CbcHmacSha512Provider standardProvider(Keyring keyring) {
    return AeadAes256CbcHmacSha512Provider.builder()
        .keyring(keyring)
        .build();
  }

  private DefaultCryptoManager standardCryptoManager(Keyring keyring) {
    AeadAes256CbcHmacSha512Provider provider = standardProvider(keyring);

    return DefaultCryptoManager.builder()
        .decrypter(provider.decrypter())
        .defaultEncrypter(provider.encrypterForKey(TEST_KEY_NAME))
        .build();
  }

  private Keyring simpleKeyring() throws Exception {
    return createKeyStoreKeyring(mapOf(TEST_KEY_NAME, testKeyBytes()));
  }

  private static byte[] testKeyBytes() {
    byte[] key = new byte[64];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }
    return key;
  }

  private void standardInitWith(DefaultCryptoManager cryptoManager) {
    env = ClusterEnvironment.builder()
        .cryptoManager(cryptoManager)
        .build();

    cluster = Cluster.connect(couchbase.getConnectionString(),
        clusterOptions(couchbase.getUsername(), couchbase.getPassword())
            .environment(env));

    Bucket bucket = cluster.bucket(BUCKET_NAME);
    bucket.waitUntilReady(Duration.ofSeconds(15));
    collection = bucket.defaultCollection();
  }

  private static Keyring createKeyStoreKeyring(Map<String, byte[]> keys) throws Exception {
    // Test KeyStore population code by first writing the keystore file
    File keyStoreFile = writeToTempKeyStore(keys);

    KeyStore keyStore = KeyStore.getInstance("JCEKS");
    try (FileInputStream is = new FileInputStream(keyStoreFile)) {
      keyStore.load(is, KEYSTORE_INTEGRITY_PASSWORD.toCharArray());
      return new KeyStoreKeyring(keyStore, KEYSTORE_PROTECTION_PASSWORD);
    }
  }

  private static File writeToTempKeyStore(Map<String, byte[]> keys) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("JCEKS");
    keyStore.load(null); // initialize new empty key store

    for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
      String name = entry.getKey();
      byte[] bytes = entry.getValue();
      KeyStoreKeyring.setSecretKey(keyStore, name, bytes,
          KEYSTORE_PROTECTION_PASSWORD.apply(name).toCharArray());
    }

    File keyStoreFile = Files.createTempFile("test-key-store", ".jceks").toFile();
    keyStoreFile.deleteOnExit();

    try (OutputStream os = new FileOutputStream(keyStoreFile)) {
      keyStore.store(os, KEYSTORE_INTEGRITY_PASSWORD.toCharArray());
    }

    return keyStoreFile;
  }
}
