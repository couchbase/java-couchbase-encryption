package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static com.couchbase.client.core.util.CbCollections.mapOf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AeadAes256CbcHmacSha512ProviderTest {
  @Test
  void encryptAndDecrypt() throws Exception {
    final byte[] plaintext = "\"The enemy knows the system.\"".getBytes(UTF_8);

    final Map<String, Object> encrypted = mapOf(
        "alg", "AEAD_AES_256_CBC_HMAC_SHA512",
        "kid", "test-key",
        "ciphertext", "GvOMLcK5b/3YZpQJI0G8BLm98oj20ZLdqKDV3MfTuGlWL4R5p5Deykuv2XLW4LcDvnOkmhuUSRbQ8QVEmbjq43XHdOm3ColJ6LzoaAtJihk=");

    AeadAes256CbcHmacSha512Provider provider = EncryptionTestHelper.provider();

    CryptoManager cryptoManager = DefaultCryptoManager.builder()
        .decrypter(provider.decrypter())
        .defaultEncrypter(provider.encrypterForKey("test-key"))
        .build();

    assertEquals(encrypted, cryptoManager.encrypt(plaintext, null));
    assertArrayEquals(plaintext, cryptoManager.decrypt(encrypted));
  }
}

