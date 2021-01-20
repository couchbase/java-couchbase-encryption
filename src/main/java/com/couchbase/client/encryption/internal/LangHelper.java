/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

/**
 * A mishmash of convenience methods from core-io.
 * They're duplicated here to avoid dependencies
 * on the Java SDK's internal API.
 */
public class LangHelper {

  public static <T extends Throwable> void throwIfInstanceOf(Throwable t, Class<T> clazz) throws T {
    requireNonNull(t);
    if (clazz.isInstance(t)) {
      throw clazz.cast(t);
    }
  }

  public static String removeStart(String s, String removeMe) {
    if (s == null || removeMe == null) {
      return s;
    }
    return s.startsWith(removeMe) ? s.substring(removeMe.length()) : s;
  }

  public static String nullToEmpty(String s) {
    return s == null ? "" : s;
  }

  public static <T> T defaultIfNull(T value, T defaultValue) {
    return value == null ? defaultValue : value;
  }

  public static <T> T defaultIfNull(T value, Supplier<? extends T> defaultValueSupplier) {
    requireNonNull(defaultValueSupplier);
    return value == null ? defaultValueSupplier.get() : value;
  }

  public static boolean isNullOrEmpty(String s) {
    return s == null || s.isEmpty();
  }

  public static <T> List<T> copyToUnmodifiableList(Collection<T> c) {
    return isNullOrEmpty(c) ? emptyList() : unmodifiableList(new ArrayList<>(c));
  }

  public static boolean isNullOrEmpty(Collection<?> c) {
    return c == null || c.isEmpty();
  }

}
