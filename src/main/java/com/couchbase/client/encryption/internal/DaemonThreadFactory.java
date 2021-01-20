/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class DaemonThreadFactory implements ThreadFactory {
  private static final AtomicInteger poolId = new AtomicInteger();

  private final AtomicInteger nextId = new AtomicInteger();
  private final String prefix;

  public DaemonThreadFactory(String poolName) {
    prefix = poolName + '-' + poolId.incrementAndGet() + '-';
  }

  @Override
  public Thread newThread(Runnable r) {
    Thread t = new Thread(r, prefix + nextId.incrementAndGet());
    if (!t.isDaemon()) {
      t.setDaemon(true);
    }
    return t;
  }
}
