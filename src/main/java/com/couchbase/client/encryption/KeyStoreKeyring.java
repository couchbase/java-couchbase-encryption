/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import static java.util.Collections.unmodifiableMap;
import static java.util.Objects.requireNonNull;

/**
 * A Keyring backed by a Java KeyStore.
 */
public class KeyStoreKeyring implements ListableKeyring {
  private static final Logger log = LoggerFactory.getLogger(KeyStoreKeyring.class);

  private final Map<String, Key> keyNameToKey;

  /**
   * Creates a new Keyring backed by the given Java KeyStore
   * (either JCEKS or PKCS12).
   * <p>
   * The KeyStore must already be initialized. Subsequent changes
   * to the KeyStore do not affect the Keyring.
   * <p>
   * Keys must be of type {@link KeyStore.SecretKeyEntry}
   * in RAW format (just the bytes, please). The key algorithm is ignored.
   *
   * @param keyStore The backing key store.
   * @param keyNameToPassword A callback function that takes a key name
   * and returns the password that protects the key, or returns null if the password is unknown.
   */
  public KeyStoreKeyring(KeyStore keyStore, Function<String, String> keyNameToPassword) throws KeyStoreException {
    // Copy all keys out of the KeyStore to avoid concurrency issues
    // that would arise if the KeyStore were modified externally after this point,
    // and also so that warnings about unrecoverable keys are logged on startup
    // instead of after the first retrieval attempt.
    this.keyNameToKey = unmodifiableMap(getAllSecretKeys(keyStore, keyNameToPassword));
  }

  @Override
  public Optional<Key> get(String keyId) {
    return Optional.ofNullable(keyNameToKey.get(keyId));
  }

  @Override
  public Set<String> keyIds() {
    return keyNameToKey.keySet();
  }

  public Map<String, Key> getAllSecretKeys(KeyStore keyStore, Function<String, String> keyNameToPassword) throws KeyStoreException {
    requireNonNull(keyNameToPassword);

    final Map<String, Key> aliasToKey = new HashMap<>();

    for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
      final String alias = aliases.nextElement();

      // ignore certificates
      if (!keyStore.isKeyEntry(alias)) {
        continue;
      }

      final String password = keyNameToPassword.apply(alias);
      if (password == null) {
        log.debug("Ignoring key '{}' because the password is not known.", alias);
        continue;
      }

      try {
        final KeyStore.Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
        if (!(entry instanceof KeyStore.SecretKeyEntry)) {
          log.debug("Ignoring key '{}' because the KeyStore entry type is not SecretKeyEntry; actual type is {}",
              alias, entry.getClass().getSimpleName());
          continue;
        }

        byte[] keyBytes = ((KeyStore.SecretKeyEntry) entry).getSecretKey().getEncoded();
        aliasToKey.put(alias, new Key(alias, keyBytes));

      } catch (Exception e) {
        log.warn("Ignoring key '{}' because it could not be retrieved (wrong password?)", alias, e);
      }
    }

    return aliasToKey;
  }

  /**
   * Convenience method for populating a KeyStore.
   *
   * @implNote {@link KeyStoreKeyring} does not care about a key's algorithm name.
   * <p>
   * JCEKS allows arbitrary algorithm names. If you know you're working
   * with a JCEKS KeyStore, the algorithm name can be "UNKNOWN" or "CUSTOM"
   * or whatever you want.
   * <p>
   * A PKCS12 KeyStore, on the other hand, requires non-standard algorithms
   * to be expressed as an Object Identifier (OID).
   * <p>
   * Using an OID lets this method be compatible with either keystore type.
   * OIDs prefixed by 1.3.9990 through 9999 are reserved for private ad-hoc usage,
   * which seems appropriate in this case.
   */
  public static void setSecretKey(KeyStore keystore, String keyAlias, byte[] keyBytes, char[] keyPassword) throws KeyStoreException {
    // The ASCII value for wildcard "*" happens to be 42 :-)
    final String keyAlgorithm = "OID.1.3.9999.42";

    keystore.setEntry(keyAlias,
        new KeyStore.SecretKeyEntry(new SecretKeySpec(keyBytes, keyAlgorithm)),
        new KeyStore.PasswordProtection(keyPassword));
  }
}
