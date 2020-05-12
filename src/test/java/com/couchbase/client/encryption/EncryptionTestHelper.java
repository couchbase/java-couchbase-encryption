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

package com.couchbase.client.encryption;

import com.couchbase.client.core.deps.io.netty.buffer.ByteBufUtil;

import java.security.SecureRandom;
import java.util.Base64;

import static com.couchbase.client.core.util.CbCollections.mapOf;

class EncryptionTestHelper {
  private EncryptionTestHelper() {
    throw new AssertionError("not instantiable");
  }

  private static Keyring keyring = Keyring.fromMap(mapOf("test-key", ByteBufUtil.decodeHexDump(
      ("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" +
          "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f" +
          "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f" +
          "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f").replaceAll("\\s", ""))));

  private static byte[] iv = ByteBufUtil.decodeHexDump(
      ("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04").replaceAll("\\s", ""));

  private static AeadAes256CbcHmacSha512Provider provider = AeadAes256CbcHmacSha512Provider.builder()
      .keyring(EncryptionTestHelper.keyring())
      .secureRandom(EncryptionTestHelper.secureRandom())
      .build();


  public static Keyring keyring() {
    return keyring;
  }

  public static SecureRandom secureRandom() {
    return new FakeSecureRandom(iv);
  }

  public static AeadAes256CbcHmacSha512Provider provider() {
    return provider;
  }

  public static void main(String[] args) {
    System.out.println(Base64.getEncoder().encodeToString(("" +
        "\"The enemy knows the system.\"").getBytes()));
  }
}
