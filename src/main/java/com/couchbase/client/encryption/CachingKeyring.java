/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Wraps another Keyring and caches the results of "get" calls.
 * <p>
 * Requires the optional {@code com.github.ben-manes.caffeine:caffeine}
 * dependency to be on the class path.
 */
public class CachingKeyring implements Keyring {
  private final Cache<String, Optional<Key>> cache;
  private final Keyring wrapped;

  public CachingKeyring(Duration expiry, int maxEntries, Keyring wrapped) {
    this(Caffeine.newBuilder()
            .expireAfterWrite(expiry)
            .maximumSize(maxEntries)
            .build(),
        wrapped);
  }

  public CachingKeyring(Cache<String, Optional<Key>> cache, Keyring wrapped) {
    this.wrapped = requireNonNull(wrapped);
    this.cache = requireNonNull(cache);
  }

  @Override
  public Optional<Key> get(String keyId) {
    return cache.get(keyId, wrapped::get);
  }
}
