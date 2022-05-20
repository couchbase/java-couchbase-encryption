# 3.1.0

- Deprecated `Keyring.rotating()` because it is unsuitable for distributed
- applications, because it always encrypts using the latest version of the key,
- regardless of whether that version is available yet on other nodes.

- Added `RotatingKeyring` and `FilesystemRotatingKeyring` to address the
- shortcomings of `Keyring.rotating()`.

- Made `FilesystemKeyring.KeyFileFormat` public. Now it's actually possible
- to instantiate a `FilesystemKeyring` from outside the package.

# 3.0.0

- Initial release of Field-Level Encryption for Couchbase Java SDK 3.
