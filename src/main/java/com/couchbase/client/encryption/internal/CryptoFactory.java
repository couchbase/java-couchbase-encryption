/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;
import com.couchbase.client.encryption.errors.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.Provider;
import java.util.Optional;

/**
 * A factory for Ciphers and Macs that falls back to the default
 * security provider chain if no security provider is specified.
 */
@Stability.Internal
class CryptoFactory {
  private final Optional<Provider> provider;

  CryptoFactory(Provider provider) {
    this.provider = Optional.ofNullable(provider);
  }

  Cipher newCipher(String name) {
    try {
      return provider.isPresent()
          ? Cipher.getInstance(name, provider.get())
          : Cipher.getInstance(name);
    } catch (Exception e) {
      throw new CryptoException("Failed to get instance of cipher '" + name + "'", e);
    }
  }

  Mac newMac(String name) {
    try {
      return provider.isPresent()
          ? Mac.getInstance(name, provider.get())
          : Mac.getInstance(name);
    } catch (Exception e) {
      throw new CryptoException("Failed to get instance of mac '" + name + "'", e);
    }
  }

  @Override
  public String toString() {
    return "CryptoFactory{" +
        "provider=" + provider +
        '}';
  }
}
