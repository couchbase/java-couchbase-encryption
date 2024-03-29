/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.encryption.errors.CryptoKeyNotFoundException;
import com.couchbase.client.encryption.internal.KeyImpl;
import com.couchbase.client.encryption.internal.Zeroizer;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import static com.couchbase.client.encryption.internal.LangHelper.copyToUnmodifiableList;
import static com.couchbase.client.encryption.internal.LangHelper.removeStart;
import static java.util.Objects.requireNonNull;

/**
 * Provides access to encryption keys.
 * <p>
 * This interface has several static methods for creating keyrings and
 * decorating them with various behaviors.
 * <p>
 * For maximum compatibility across implementations, a key name should:
 * <ul>
 * <li>contain no more than 240 characters
 * <li>contain only lowercase alphanumeric characters, ‘-’, or ‘.’
 * <li>start with an alphanumeric character
 * <li>end with an alphanumeric character
 * </ul>
 * <p>
 *
 * @see #caching(Duration, int, Keyring)
 * @see #reloading(Duration, Supplier)
 * @see #composite(Keyring...)
 * @see #fromMap(Map)
 * @see RotatingKeyring
 * @see FilesystemRotatingKeyring
 */
public interface Keyring {

  /**
   * An encryption key.
   * <p>
   * Create new instances by calling {@link #create(String, byte[])}.
   */
  interface Key {
    /**
     * Creates a new key with the given ID and material,
     * then zeroizes the given material.
     */
    static Key create(String id, byte[] material) {
      try (Zeroizer zeroizer = new Zeroizer()) {
        return new KeyImpl(id, zeroizer.add(material));
      }
    }

    /**
     * Returns the fully-qualified name of this key.
     */
    String id();

    /**
     * Returns a copy of the key material.
     * <p>
     * Caller is responsible for zeroizing the returned byte array.
     */
    byte[] bytes();
  }

  /**
   * Returns the requested key.
   * <p>
   * If the keyring supports key rotation and the key ID does not
   * include a version, the keyring returns the latest version of
   * the key. The caller should always call {@link Key#id()} to get
   * the returned key's actual ID.
   *
   * @see RotatingKeyring
   */
  Optional<Key> get(String keyId);

  /**
   * Returns the requested key or throws an exception if not found.
   *
   * @throws CryptoKeyNotFoundException if the key was not found.
   */
  default Key getOrThrow(String keyId) {
    return get(keyId).orElseThrow(() ->
        new CryptoKeyNotFoundException("Failed to locate crypto key '" + keyId + "'"));
  }

  /**
   * Returns the given keyring decorated to cache "get" results.
   * <p>
   * Useful if fetching a key is expensive.
   * <p>
   * If multiple decorators are applied to a keyring, caching should be
   * the outermost decorator.
   */
  static Keyring caching(Duration expiry, int maxEntries, Keyring wrapped) {
    requireNonNull(wrapped);
    Cache<String, Optional<Key>> cache = Caffeine.newBuilder()
        .expireAfterWrite(expiry)
        .maximumSize(maxEntries)
        .build();
    return keyId -> cache.get(keyId, wrapped::get);
  }

  /**
   * Returns a keyring wrapper whose backing keyring is periodically refreshed
   * by calling the given supplier.
   */
  static Keyring reloading(Duration reloadInterval, Supplier<Keyring> loader) {
    requireNonNull(loader);
    Cache<String, Keyring> cache = Caffeine.newBuilder()
        .expireAfterWrite(reloadInterval)
        .maximumSize(1)
        .build();
    return keyId -> cache.get("", ignore -> loader.get()).get(keyId);
  }

  /**
   * Returns the given keyring decorated to support key rotation.
   * <p>
   * The resulting keyring first looks for a key whose name exactly matches
   * the requested name, and returns the matching key if found.
   * Otherwise the keyring treats the requested name as a "base name"
   * and returns the latest version of the key with that base name.
   * <p>
   * The names of the keys in the Keyring must follow a special naming convention.
   * <p>
   * Let's say you have an {@link Encrypter} that refers to a key series by its
   * base name, "myKey". The keyring may contain several versions of that key.
   * The qualified name of a key in the series consists of the base name
   * followed by a delimiter and then a version identifier.
   * <p>
   * The choice of delimiter and version identifier is up to you. The delimiter
   * must not occur in any key's base name. Since the delimiter is part of the
   * full key name, it may only contain characters supported by the backing keyring.
   * <p>
   * The recommended version ID scheme is to use an ISO 8601 date like "2020-01-24".
   * These dates are easy to generate and can be compared using {@link Comparator#naturalOrder()}.
   * If you chose a version ID scheme where the natural order does not accurately reflect
   * the ordering between version IDs, you must specify a different comparator.
   * <p>
   * If you use "--" as the delimiter and ISO 8601 dates as the version IDs,
   * the names of the keys in the backing keyring should look like this:
   * <ul>
   * <li>myKey--2020-01-01
   * <li>myKey--2020-02-01
   * <li>myKey--2020-03-01
   * </ul>
   * When encrypting a new value, the {@code Encrypter} asks for the latest
   * version of the key by passing its base name. When decrypting, the decrypter
   * asks for a specific version by passing a fully-qualified key name.
   * <pre>
   * keyring.get("myKey") --> "myKey--2020-03-01" (latest version)
   * keyring.get("myKey--2020-02-01") --> "myKey--2020-02-01" (requested version)
   * </pre>
   *
   * @param wrapped the backing keyring
   * @param versionDelimiter separates a key's base name from its version
   * @param versionOrder Compares key versions. The greater version is considered more recent.
   * For ISO 8601 dates you can use {@link Comparator#naturalOrder()}.
   *
   * @deprecated This implementation overlooks an important detail; it lacks the ability to add a new
   * version of a key without using it to encrypt new data. This is significant because the new key
   * must be distributed to all application nodes before any node uses it to encrypt data, otherwise
   * the other nodes will not be able to decrypt the data. Instead of this decorator method,
   * please use {@link FilesystemRotatingKeyring} or your own custom subclass of {@link RotatingKeyring}.
   * These classes let you designate a version of the key as "primary", and use the primary version to encrypt
   * data even if it's not the latest version of the key.
   */
  @Deprecated
  static Keyring rotating(String versionDelimiter, Comparator<String> versionOrder, ListableKeyring wrapped) {
    requireNonNull(wrapped);
    requireNonNull(versionDelimiter);

    if (versionDelimiter.isEmpty()) {
      throw new IllegalArgumentException("Version delimiter must not be empty.");
    }

    return keyId -> {
      final Optional<Key> exactMatch = wrapped.get(keyId);
      if (exactMatch.isPresent()) {
        return exactMatch;
      }

      final String versionedKeyPrefix = keyId + versionDelimiter;
      final String latestVersion = wrapped.keyIds().stream()
          .filter(keyName -> keyName.startsWith(versionedKeyPrefix))
          .map(keyName -> removeStart(keyName, versionedKeyPrefix))
          .max(versionOrder)
          .orElse(null);
      return latestVersion == null ? Optional.empty() : wrapped.get(versionedKeyPrefix + latestVersion);
    };
  }

  /**
   * Returns a composite keyring that consults the given keyrings in order.
   */
  static Keyring composite(Keyring... keyrings) {
    return composite(Arrays.asList(keyrings));
  }

  /**
   * Returns a composite keyring that consults the given keyrings in order.
   */
  static Keyring composite(List<Keyring> keyrings) {
    if (keyrings.stream().anyMatch(Objects::isNull)) {
      throw new IllegalArgumentException("Keyring chain may not contain null keyring.");
    }

    final List<Keyring> chain = copyToUnmodifiableList(keyrings);

    return keyId -> {
      for (Keyring keyring : chain) {
        Optional<Key> key = keyring.get(keyId);
        if (key.isPresent()) {
          return key;
        }
      }
      return Optional.empty();
    };
  }

  /**
   * Returns a static keyring with the given keys.
   * <p>
   * Changes to the map are not reflected in the keyring.
   */
  static ListableKeyring fromMap(Map<String, byte[]> keyNameToBytes) {
    final Map<String, Key> nameToKey = new HashMap<>();
    keyNameToBytes.forEach((k, v) -> nameToKey.put(k, Key.create(k, v)));

    return new ListableKeyring() {
      @Override
      public Set<String> keyIds() {
        return nameToKey.keySet();
      }

      @Override
      public Optional<Key> get(String keyId) {
        return Optional.ofNullable(nameToKey.get(keyId));
      }
    };
  }
}
