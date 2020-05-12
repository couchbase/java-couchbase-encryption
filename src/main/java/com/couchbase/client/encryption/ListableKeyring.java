/*
 * Copyright (c) 2020 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement v7
 * which may be found at https://www.couchbase.com/ESLA01162020.
 */

package com.couchbase.client.encryption;

import java.util.Collection;

/**
 * A Keyring that supports listing the IDs of the keys it contains.
 * <p>
 * Can be decorated to support key rotation using {@link Keyring#rotating}
 */
public interface ListableKeyring extends Keyring {
  Collection<String> keyIds();
}
