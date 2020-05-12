/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;


import com.couchbase.client.core.encryption.CryptoManager;

import static java.util.Objects.requireNonNull;

public class EncrypterNotFoundException extends CryptoException {
  private final String alias;

  public static EncrypterNotFoundException forAlias(String alias) {
    return new EncrypterNotFoundException(alias);
  }

  private EncrypterNotFoundException(String alias) {
    super(CryptoManager.DEFAULT_ENCRYPTER_ALIAS.equals(alias)
        ? "No default encrypter was registered. Please specify an encrypter or register a default encrypter."
        : "Missing encrypter for alias '" + alias + "'");
    this.alias = requireNonNull(alias);
  }

  public String alias() {
    return alias;
  }
}
