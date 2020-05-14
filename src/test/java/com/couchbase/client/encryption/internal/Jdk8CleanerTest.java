package com.couchbase.client.encryption.internal;

import com.couchbase.client.core.deps.io.netty.util.concurrent.DefaultThreadFactory;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.fail;

class Jdk8CleanerTest {
  @Test
  void register() throws Exception {
    Jdk8Cleaner cleaner = Jdk8Cleaner.create(new DefaultThreadFactory("jdk8cleaner"));

    AtomicBoolean cleaned = new AtomicBoolean();
    // Lambda is only safe here because it doesn't capture the value of the referent.
    // Normally you'd pass an instance of a static class that implements Runnable.
    cleaner.register(new Object(), () -> cleaned.set(true));

    collectGarbageAndAssert(cleaned::get);
  }

  public static void collectGarbageAndAssert(Supplier<Boolean> condition) {
    Duration timeout = Duration.ofSeconds(15);

    long nanoTime = System.nanoTime();
    do {
      System.gc();
      if (condition.get()) {
        return;
      }
    } while (System.nanoTime() - nanoTime < timeout.toNanos());

    fail("Failed to meet condition before deadline.");
  }
}
