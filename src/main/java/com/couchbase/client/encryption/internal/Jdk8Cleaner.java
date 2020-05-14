/*
 * Copyright 2020 Couchbase, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.annotation.Stability;
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
@Stability.Internal
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
