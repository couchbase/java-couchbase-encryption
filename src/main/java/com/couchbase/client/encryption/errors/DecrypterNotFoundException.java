/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.errors;

import static java.util.Objects.requireNonNull;

public class DecrypterNotFoundException extends CryptoException {
  private final String algorithm;

  public static DecrypterNotFoundException forAlgorithm(String algorithm) {
    return new DecrypterNotFoundException(algorithm);
  }

  private DecrypterNotFoundException(String algorithm) {
    super("Missing decrypter for algorithm '" + algorithm + "'");
    this.algorithm = requireNonNull(algorithm);
  }

  public String algorithm() {
    return algorithm;
  }
}
