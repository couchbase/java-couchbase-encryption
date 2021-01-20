/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.encryption.errors.InvalidCiphertextException;
import org.springframework.vault.VaultException;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.Ciphertext;
import org.springframework.vault.support.Plaintext;

import static com.couchbase.client.encryption.internal.LangHelper.nullToEmpty;
import static java.util.Objects.requireNonNull;

/**
 * Delegates encryption and decryption to HashiCorp Vault Transit secrets engine.
 * <p>
 * Encrypted values are stored in Couchbase, but encryption and decryption are
 * handled by a Vault server. Your encryption keys never leave Vault.
 * <p>
 * Depends on the Spring Vault library. Your project must declare
 * {@code org.springframework.vault:spring-vault-core} as a dependency
 * if you want to use this provider.
 * <p>
 * You are responsible for configuring the Spring {@code VaultTemplate}.
 * For details on the various authentication and session management options, see
 * <a href="https://docs.spring.io/spring-vault/docs/current/reference/html/">
 * Spring Vault - Reference Documentation</a>.
 * <p>
 * Example usage:
 * <pre>
 * VaultEndpoint endpoint = VaultEndpoint.create("127.0.0.1", 8200);
 * endpoint.setScheme("http"); // unless Vault is configured for https
 * VaultTemplate vaultTemplate = new VaultTemplate(endpoint,
 *     new TokenAuthentication("00000000-0000-0000-0000-000000000000"));
 *
 * SpringVaultTransitProvider transit = new SpringVaultTransitProvider(
 *     vaultTemplate.opsForTransit());
 *
 * CryptoManager cryptoManager = DefaultCryptoManager.builder()
 *     .decrypter(transit.decrypter())
 *     .defaultEncrypter(transit.encrypterForKey("myKey"))
 *     .build();
 * </pre>
 */
public class SpringVaultTransitProvider {
  private static final String ALGORITHM = "HASHICORP_VAULT_TRANSIT";

  private final VaultTransitOperations transitOps;

  /**
   * @param vaultTransitOps Obtained from {@link VaultTemplate#opsForTransit()}
   */
  public SpringVaultTransitProvider(VaultTransitOperations vaultTransitOps) {
    this.transitOps = requireNonNull(vaultTransitOps);
  }

  public Decrypter decrypter() {
    return new Decrypter() {
      @Override
      public String algorithm() {
        return ALGORITHM;
      }

      @Override
      public byte[] decrypt(EncryptionResult encrypted) throws Exception {
        try {
          String keyName = encrypted.getString("kid");
          String ciphertext = encrypted.getString("ciphertext");
          return transitOps.decrypt(keyName, Ciphertext.of(ciphertext)).getPlaintext();

        } catch (VaultException e) {
          if (nullToEmpty(e.getMessage()).contains("invalid ciphertext")) {
            throw new InvalidCiphertextException("Decryption failed.", e);
          }
          throw e;
        }
      }
    };
  }

  public Encrypter encrypterForKey(String keyName) {
    return plaintext -> {
      Ciphertext ciphertext = transitOps.encrypt(keyName, Plaintext.of(plaintext));
      return EncryptionResult.forAlgorithm(ALGORITHM)
          .put("kid", keyName)
          .put("ciphertext", ciphertext.getCiphertext());
    };
  }
}
