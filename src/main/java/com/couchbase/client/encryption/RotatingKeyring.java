/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Base class for implementing Keyrings that support key rotation.
 */
public abstract class RotatingKeyring implements Keyring {
  protected final String versionDelimiter;

  /**
   * @param versionDelimiter separates a key ID's base name component from the version component.
   */
  protected RotatingKeyring(String versionDelimiter) {
    this.versionDelimiter = requireNonNull(versionDelimiter);
  }

  protected class KeyNameAndVersion {
    private final String name;
    private final String version;

    public KeyNameAndVersion(String name, String version) {
      this.name = requireNonNull(name);
      this.version = requireNonNull(version);
    }

    public String name() {
      return name;
    }

    public String version() {
      return version;
    }

    public String format() {
      return name + versionDelimiter + version;
    }

    @Override
    public String toString() {
      return format();
    }
  }

  public Optional<Key> get(String keyId) {
    KeyNameAndVersion nameAndVersion = parseKeyNameAndVersion(keyId);
    return getKeyBytes(nameAndVersion)
        .map(bytes -> Key.create(nameAndVersion.format(), bytes));
  }

  protected abstract String getPrimaryVersion(String baseName);

  protected abstract Optional<byte[]> getKeyBytes(KeyNameAndVersion keyNameAndVersion);

  protected KeyNameAndVersion parseKeyNameAndVersion(String keyId) {
    int i = keyId.indexOf(versionDelimiter);
    return i == -1
        ? new KeyNameAndVersion(keyId, getPrimaryVersion(keyId))
        : new KeyNameAndVersion(keyId.substring(0, i), keyId.substring(i + versionDelimiter.length()));
  }
}
