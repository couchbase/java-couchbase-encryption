/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Collections.newSetFromMap;
import static java.util.Objects.requireNonNull;

/**
 * Approximates Java 9's <a href="https://docs.oracle.com/javase/9/docs/api/java/lang/ref/Cleaner.html">
 * java.lang.ref.Cleaner
 * </a>
 */
public class Jdk8Cleaner {
  private static final Logger log = LoggerFactory.getLogger(Jdk8Cleaner.class);

  private final ReferenceQueue<Object> queue = new ReferenceQueue<>();
  private final Set<CleanableImpl> references = newSetFromMap(new IdentityHashMap<>());

  public static Jdk8Cleaner create(ThreadFactory factory) {
    return new Jdk8Cleaner(factory);
  }

  private Jdk8Cleaner(ThreadFactory factory) {
    Thread thread = factory.newThread(this::doRun);
    thread.start();
  }

  /**
   * Executes the given cleaning action when the object becomes phantom reachable.
   * <p>
   * The cleaning action should generally not be a lambda, since it's easy to accidentally
   * capture a reference to the object, preventing it from ever becoming phantom reachable.
   */
  public Cleanable register(Object obj, Runnable cleaningAction) {
    CleanableImpl cleanable = new CleanableImpl(obj, queue, cleaningAction);
    references.add(cleanable);
    return cleanable;
  }

  private void doRun() {
    while (true) {
      try {
        CleanableImpl r = (CleanableImpl) queue.remove();
        references.remove(r);
        r.clean();

      } catch (InterruptedException e) {
        log.info("Cleaner thread interrupted; exiting.");
        return;
      }
    }
  }

  /**
   * An object and a cleaning action registered in a Cleaner.
   */
  public interface Cleanable {
    /**
     * Unregisters the cleanable and invokes the cleaning action.
     * The cleanable's cleaning action is invoked at most once
     * regardless of the number of calls to clean.
     */
    void clean();
  }

  private static class CleanableImpl extends PhantomReference<Object> implements Cleanable {
    private final Runnable cleaningAction;
    private final AtomicBoolean alreadyCleaned = new AtomicBoolean();

    CleanableImpl(Object referent, ReferenceQueue<Object> q, Runnable cleaningAction) {
      super(referent, q);
      this.cleaningAction = requireNonNull(cleaningAction);
    }

    @Override
    public void clean() {
      if (alreadyCleaned.compareAndSet(false, true)) {
        try {
          cleaningAction.run();
        } catch (Throwable t) {
          log.error("Cleaning action threw exception", t);
        }
      }
    }
  }
}
