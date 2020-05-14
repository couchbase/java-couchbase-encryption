/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;
import com.couchbase.client.encryption.Decrypter;
import com.couchbase.client.encryption.EncryptionResult;
import com.couchbase.client.encryption.Keyring;
import com.couchbase.client.encryption.errors.CryptoKeyNotFoundException;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Decrypts messages encrypted by the legacy {@code RsaCryptoProvider} class.
 */
@Stability.Internal
public class LegacyRsaDecrypter implements Decrypter {
  private final Function<String, String> publicKeyNameToPrivateKeyName;
  private final Keyring keyring;

  public LegacyRsaDecrypter(Keyring keyring, Function<String, String> publicKeyNameToPrivateKeyName) {
    this.keyring = requireNonNull(keyring);
    this.publicKeyNameToPrivateKeyName = requireNonNull(publicKeyNameToPrivateKeyName);
  }

  @Override
  public String algorithm() {
    return "RSA-2048-OAEP-SHA1";
  }

  @Override
  public byte[] decrypt(EncryptionResult encrypted) throws Exception {
    final String kid = encrypted.getString("kid");
    final byte[] ciphertext = encrypted.getBytes("ciphertext");

    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(kid), oaepParams);
    return cipher.doFinal(ciphertext);
  }

  private String getPrivateKeyName(String publicKeyName) {
    return Optional.of(publicKeyNameToPrivateKeyName.apply(publicKeyName))
        .orElseThrow(() -> new CryptoKeyNotFoundException("No mapping to private key name found for public key '" + publicKeyName + "'"));
  }

  private RSAPrivateKey getPrivateKey(String publicKeyName) throws Exception {
    try (Zeroizer zeroizer = new Zeroizer()) {
      String privateKeyName = getPrivateKeyName(publicKeyName);
      byte[] keyBytes = zeroizer.add(keyring.getOrThrow(privateKeyName).bytes());
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
      return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }
  }
}
