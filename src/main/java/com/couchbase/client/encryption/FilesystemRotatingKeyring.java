/*
 * Copyright (c) 2021 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.encryption.errors.CryptoKeyNotFoundException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static com.couchbase.client.encryption.internal.LangHelper.substringBetween;
import static java.util.Objects.requireNonNull;

/**
 * Reads keys from filesystem. Uses a naming convention to identify
 * "primary" version of the key (the version used for encrypting new values).
 * <p>
 * There can be multiple versions of the key. Key name and version
 * are separated by delimiter
 * <p>
 * Store each key in a separate file. Contents of key file must be
 * 64 bytes from a cryptographically secure random source. Example:
 * <pre>
 * openssl rand 64 -out myKey--1.key.primary
 * </pre>
 * Configure encrypter with the base key name (for example, just "myKey").
 * The version with the primary filename extension will be used for
 * encryption and decryption. Non-primary keys are for decryption only.
 * <p>
 * To rotate a key, create a new key version (*NOT* primary) and distribute
 * it to all application nodes. When distribution is complete, rename it
 * with the primary extension, so it gets used for encryption.
 * <p>
 * For better performance, wrap this keyring using {@link Keyring#caching}.
 */
public class FilesystemRotatingKeyring extends RotatingKeyring {
  private final String filenameExtension;
  private final String primaryFilenameExtension;
  private final Path directory;

  public FilesystemRotatingKeyring(Path directory) {
    this(directory, "--", ".key", ".key.primary");
  }

  public FilesystemRotatingKeyring(Path directory, String versionDelimiter, String filenameExtension, String primaryFilenameExtension) {
    super(versionDelimiter);
    this.directory = requireNonNull(directory);
    this.filenameExtension = requireNonNull(filenameExtension);
    this.primaryFilenameExtension = requireNonNull(primaryFilenameExtension);
  }

  @Override
  protected String getPrimaryVersion(String baseName) {
    try (Stream<Path> paths = Files.list(directory)){
      return paths
          .map(path -> substringBetween(
                  path.getFileName().toString(),
                  versionDelimiter,
                  primaryFilenameExtension
              )
          )
          .filter(Objects::nonNull)
          .findFirst()
          .orElseThrow(() -> new CryptoKeyNotFoundException("Failed to locate primary version of key " + baseName));
    } catch (IOException e) {
      throw new CryptoKeyNotFoundException("Failed to locate primary version of key " + baseName, e);
    }
  }

  @Override
  protected Optional<byte[]> getKeyBytes(KeyNameAndVersion keyNameAndVersion) {
    String nameIfPrimary = keyNameAndVersion.format() + primaryFilenameExtension;
    String nameIfNotPrimary = keyNameAndVersion.format() + filenameExtension;
    try (Stream<Path> paths = Files.list(directory)){
      return paths
          .filter(path -> {
            String filename = path.getFileName().toString();
            return filename.equals(nameIfNotPrimary) || filename.equals(nameIfPrimary);
          })
          .map(path -> {
            try {
              return Files.readAllBytes(path);
            } catch (IOException e) {
              throw new RuntimeException("Failed to read crypto key " + keyNameAndVersion.format(), e);
            }
          })
          .findFirst();
    } catch (IOException e) {
      throw new RuntimeException("Failed to locate crypto key " + keyNameAndVersion.format(), e);
    }
  }
}
