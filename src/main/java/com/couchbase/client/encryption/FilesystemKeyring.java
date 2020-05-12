/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import com.couchbase.client.core.deps.io.netty.buffer.ByteBufUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collection;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;
import static java.util.stream.Collectors.toList;

/**
 * Reads keys from individual files under a common root directory.
 * <p>
 * Suitable for containerized environments where secrets can be
 * injected into the filesystem.
 */
public class FilesystemKeyring implements ListableKeyring {
  private static final Logger log = LoggerFactory.getLogger(FilesystemKeyring.class);

  private final Path basedir;
  private final KeyFileFormat format;

  @Override
  public Collection<String> keyIds() {
    try {
      return Files.list(basedir)
          .map(path -> path.toFile().getName())
          .filter(filename -> !filename.startsWith("."))
          .collect(toList());

    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  interface KeyFileFormat {
    byte[] decode(byte[] fileBytes);

    KeyFileFormat RAW = bytes -> bytes;

    KeyFileFormat HEX = bytes -> ByteBufUtil.decodeHexDump(
        removeWhitespace(new String(bytes, US_ASCII)));

    KeyFileFormat BASE64 = bytes -> Base64.getMimeDecoder().decode(bytes);
  }

  public FilesystemKeyring(String basedir, KeyFileFormat format) {
    this(Paths.get(basedir), format);
  }

  public FilesystemKeyring(Path basedir, KeyFileFormat format) {
    this.basedir = requireNonNull(basedir).toAbsolutePath();
    this.format = requireNonNull(format);

    // fail fast if not a directory, etc.
    keyIds();
  }

  @Override
  public Optional<Key> get(String keyId) {
    final Path keyFile = basedir.resolve(keyId);

    try {
      final byte[] fileBytes = Files.readAllBytes(keyFile);
      return Optional.of(new Key(keyId, format.decode(fileBytes)));

    } catch (FileNotFoundException | NoSuchFileException e) {
      log.debug("Failed to get key '{}'", keyId, e);
      return Optional.empty();

    } catch (IOException e) {
      throw new RuntimeException("Failed to get key '" + keyId + "'", e);
    }
  }

  private static String removeWhitespace(String s) {
    return s.replaceAll("\\s", "");
  }
}
