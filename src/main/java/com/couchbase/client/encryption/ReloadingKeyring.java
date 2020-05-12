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
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * A keyring wrapper whose backing keyring is periodically refreshed by
 * calling a supplier.
 * <p>
 * Requires the optional {@code com.github.ben-manes.caffeine:caffeine}
 * dependency to be on the class path.
 */
public class ReloadingKeyring implements Keyring {
  private final Cache<String, Keyring> cache;
  private final Supplier<Keyring> loader;

  public ReloadingKeyring(Duration reloadInterval, Supplier<Keyring> loader) {
    this.cache = Caffeine.newBuilder()
        .expireAfterWrite(reloadInterval)
        .maximumSize(1)
        .build();
    this.loader = requireNonNull(loader);

    // fail fast
    requireNonNull(getKeyring());
  }

  @Override
  public Optional<Key> get(String keyId) {
    return getKeyring().get(keyId);
  }

  private Keyring getKeyring() {
    return cache.get("", ignore -> loader.get());
  }
}
