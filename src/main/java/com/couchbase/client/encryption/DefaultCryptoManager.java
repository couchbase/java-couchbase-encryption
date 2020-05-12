/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.encryption.CryptoManager;
import com.couchbase.client.core.util.Validators;
import com.couchbase.client.encryption.errors.CryptoException;
import com.couchbase.client.encryption.errors.DecrypterNotFoundException;
import com.couchbase.client.encryption.errors.EncrypterNotFoundException;
import com.couchbase.client.encryption.internal.LegacyAesDecrypter;
import com.couchbase.client.encryption.internal.LegacyRsaDecrypter;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static com.couchbase.client.core.util.CbCollections.isNullOrEmpty;
import static com.couchbase.client.core.util.CbObjects.defaultIfNull;
import static com.couchbase.client.core.util.CbStrings.removeStart;
import static com.couchbase.client.core.util.CbThrowables.throwIfInstanceOf;
import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;

/**
 * Maintains a registry of encrypters and decrypters.
 * <p>
 * New instances may be created via the builder returned by {@link #builder()}.
 */
public class DefaultCryptoManager implements CryptoManager {
  private final String encryptedFieldNamePrefix;
  private final Map<String, Encrypter> aliasToEncrypter;
  private final Map<String, Decrypter> algorithmToDecrypter;

  public static class Builder {
    private String encryptedFieldNamePrefix = DEFAULT_ENCRYPTED_FIELD_NAME_PREFIX;
    private final Map<String, Decrypter> algorithmToDecrypter = new HashMap<>();
    private final Map<String, Encrypter> aliasToEncrypter = new HashMap<>();

    public Builder decrypter(Decrypter decrypter) {
      final Decrypter previouslyRegistered = algorithmToDecrypter.putIfAbsent(decrypter.algorithm(), decrypter);
      if (previouslyRegistered != null) {
        throw new IllegalStateException("Algorithm '" + decrypter.algorithm() + "' is already associated with decrypter " + previouslyRegistered);
      }
      return this;
    }

    public Builder encrypter(String alias, Encrypter encrypter) {
      Validators.notNullOrEmpty(alias, "Encrypter alias");
      final Encrypter previouslyRegistered = aliasToEncrypter.putIfAbsent(alias, encrypter);
      if (previouslyRegistered != null) {
        throw new IllegalStateException("Encrypter alias '" + alias + "' is already associated with " + previouslyRegistered);
      }
      return this;
    }

    public Builder defaultEncrypter(Encrypter encrypter) {
      return encrypter(DEFAULT_ENCRYPTER_ALIAS, encrypter);
    }

    /**
     * Registers decrypters for reading fields encrypted by
     * {@code Aes128CryptoProvider} and {@code Aes256CryptoProvider}
     * which are now obsolete.
     * <p>
     * There is no need to call this method unless you are upgrading
     * from from version 2.x of this library and have data encrypted
     * by one of those obsolete AES providers.
     *
     * @param encryptionKeyNameToSigningKeyName A function that when given the name of
     * an encryption key, returns the name of the associated signing key (or null if unknown).
     * Historically this association was established via the {@code KeyStoreProvider},
     * but that component isn't around anymore.
     */
    public Builder legacyAesDecrypters(Keyring keyring, Function<String, String> encryptionKeyNameToSigningKeyName) {
      decrypter(LegacyAesDecrypter.aes128(keyring, encryptionKeyNameToSigningKeyName));
      decrypter(LegacyAesDecrypter.aes256(keyring, encryptionKeyNameToSigningKeyName));
      return this;
    }

    /**
     * Registers a decrypter for reading fields encrypted by
     * {@code RsaCryptoProvider} which is now obsolete.
     * <p>
     * There is no need to call this method unless you are upgrading
     * from from version 2.x of this library and have data encrypted
     * by the obsolete RSA provider.
     *
     * @param publicKeyNameToPrivateKeyName A function that when given the name of
     * a public key, returns the name of the associated private key (or null if unknown).
     * Historically this association was established via the {@code KeyStoreProvider},
     * but that component isn't around anymore.
     */
    public Builder legacyRsaDecrypter(Keyring keyring, Function<String, String> publicKeyNameToPrivateKeyName) {
      return decrypter(new LegacyRsaDecrypter(keyring, publicKeyNameToPrivateKeyName));
    }

    /**
     * Specify the string to prepend to a JSON Object's field name to indicate the field
     * holds an encrypted value.
     * <p>
     * Optional. If this method is not called, the standard prefix
     * {@value #DEFAULT_ENCRYPTED_FIELD_NAME_PREFIX} is used.
     */
    public Builder encryptedFieldNamePrefix(String encryptedFieldNamePrefix) {
      Validators.notNullOrEmpty(encryptedFieldNamePrefix, "Encrypted field prefix");
      this.encryptedFieldNamePrefix = encryptedFieldNamePrefix;
      return this;
    }

    public DefaultCryptoManager build() {
      return new DefaultCryptoManager(algorithmToDecrypter, aliasToEncrypter, encryptedFieldNamePrefix);
    }
  }

  private DefaultCryptoManager(
      Map<String, Decrypter> algorithmToDecrypter,
      Map<String, Encrypter> aliasToEncrypter,
      String encryptedFieldNamePrefix) {

    this.algorithmToDecrypter = unmodifiableMap(new HashMap<>(algorithmToDecrypter));
    this.aliasToEncrypter = unmodifiableMap(new HashMap<>(aliasToEncrypter));
    this.encryptedFieldNamePrefix = requireNonNull(encryptedFieldNamePrefix);
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public Map<String, Object> encrypt(byte[] plaintext, String encrypterAlias) {
    try {
      final Encrypter encrypter = getEncrypterByAlias(encrypterAlias);
      final EncryptionResult encrypted = encrypter.encrypt(plaintext);
      return encrypted.asMap();

    } catch (Exception e) {
      throwIfInstanceOf(e, CryptoException.class);
      throw new CryptoException("Encryption failed", e);
    }
  }

  @Override
  public byte[] decrypt(Map<String, Object> encryptedNode) {
    try {
      final EncryptionResult encrypted = EncryptionResult.fromMap(encryptedNode);
      return getDecrypter(encrypted).decrypt(encrypted);

    } catch (Exception e) {
      throwIfInstanceOf(e, CryptoException.class);
      throw new CryptoException("Decryption failed", e);
    }
  }

  @Override
  public String mangle(String fieldName) {
    return encryptedFieldNamePrefix + fieldName;
  }

  @Override
  public String demangle(String fieldName) {
    return removeStart(fieldName, encryptedFieldNamePrefix);
  }

  @Override
  public boolean isMangled(String fieldName) {
    return fieldName.startsWith(encryptedFieldNamePrefix);
  }

  /**
   * Returns the encrypter registered under the given alias.
   *
   * @throws EncrypterNotFoundException if no decrypter was registered under the given alias
   */
  private Encrypter getEncrypterByAlias(String alias) {
    alias = defaultIfNull(alias, CryptoManager.DEFAULT_ENCRYPTER_ALIAS);

    final Encrypter encrypter = aliasToEncrypter.get(alias);
    if (encrypter != null) {
      return encrypter;
    }

    throw EncrypterNotFoundException.forAlias(alias);
  }

  /**
   * Returns the decrypter whose algorithm matches the algorithm of the given encryption result.
   *
   * @throws DecrypterNotFoundException if there's no decrypter registered for the algorithm
   */
  private Decrypter getDecrypter(EncryptionResult encrypted) {
    final String alg = encrypted.getAlgorithm();
    if (isNullOrEmpty(alg)) {
      throw new IllegalArgumentException("Encryption result is missing algorithm attribute.");
    }

    final Decrypter decrypter = algorithmToDecrypter.get(alg);
    if (decrypter == null) {
      throw DecrypterNotFoundException.forAlgorithm(alg);
    }

    return decrypter;
  }

  @Override
  public String toString() {
    return "DefaultCryptoManager{" +
        "encryptedFieldNamePrefix='" + encryptedFieldNamePrefix + '\'' +
        ", aliasToEncrypter=" + aliasToEncrypter +
        ", algorithmToDecrypter=" + algorithmToDecrypter +
        '}';
  }
}
