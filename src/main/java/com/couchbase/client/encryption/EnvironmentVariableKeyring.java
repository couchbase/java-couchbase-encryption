/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import java.util.Base64;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Reads keys from environment variables.
 * <p>
 * Environment variable value must be the Base64-encoded form of the key.
 */
public class EnvironmentVariableKeyring implements Keyring {
  private final Function<String, String> keyNameToEnvironmentVariableName;

  /**
   * Derives environment variable name from key name by replacing
   * '.' and '-' characters in the key name with underscores.
   */
  public EnvironmentVariableKeyring() {
    this(keyName -> keyName.replaceAll("[.-]", "_"));
  }

  /**
   * Derives environment variable name from key name by applying
   * the given mapping function.
   */
  public EnvironmentVariableKeyring(Function<String, String> keyNameToEnvironmentVariableName) {
    this.keyNameToEnvironmentVariableName = requireNonNull(keyNameToEnvironmentVariableName);
  }

  @Override
  public Optional<Key> get(String keyId) {
    final String varName = keyNameToEnvironmentVariableName.apply(keyId);
    return Optional.ofNullable(System.getenv(varName))
        .map(value -> new Key(keyId, Base64.getMimeDecoder().decode(value)));
  }
}
