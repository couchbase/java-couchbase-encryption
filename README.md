# Field-Level Encryption for Couchbase Java SDK

This library adds support for Field-Level Encryption (FLE) to the Couchbase
Java SDK. It includes cryptographic algorithms and keyrings
you can use out of the box, and provides a framework for implementing
your own crypto components.

_Use of this software is subject to the
[Couchbase Inc. Enterprise Subscription License Agreement v7](https://www.couchbase.com/ESLA01162020)._

## Compatibility

Couchbase Java SDK version `3.0.5` or later is required.

## Maven Coordinates

```xml
<dependency>
    <groupId>com.couchbase.client</groupId>
    <artifactId>couchbase-encryption</artifactId>
    <version>${version}</version>
</dependency>
```

### Optional Dependencies

To reduce the footprint of this library, some of its dependencies
are optional. Using certain features requires adding additional dependencies
to your project.

HashiCorp Vault Transit integration requires [Spring Vault](https://docs.spring.io/spring-vault/docs/current/reference/html/):

```xml
<dependency>
    <groupId>org.springframework.vault</groupId>
    <artifactId>spring-vault-core</artifactId>
    <version>2.2.2.RELEASE</version>
</dependency>
```

## Configuration

To enable Field-Level Encryption, supply a `CryptoManager` when configuring
the Java SDK's `ClusterEnvironment`.

```java
KeyStore javaKeyStore = loadJavaKeyStore();
Keyring keyring = new KeyStoreKeyring(javaKeyStore, keyName -> "swordfish");

// AES-256 authenticated with HMAC SHA-512. Requires a 64-byte key.
AeadAes256CbcHmacSha512Provider provider = AeadAes256CbcHmacSha512Provider.builder()
    .keyring(keyring)
    .build();

CryptoManager cryptoManager = DefaultCryptoManager.builder()
    .decrypter(provider.decrypter())
    .defaultEncrypter(provider.encrypterForKey("myKey"))
    .build();

ClusterEnvironment env = ClusterEnvironment.builder()
    .cryptoManager(cryptoManager)
    .build();

Cluster cluster = Cluster.connect("localhost",
    ClusterOptions.clusterOptions("username", "password")
        .environment(env));
```

## Usage

Two modes of operation are available: transparent encryption/decryption
during Jackson data binding, and manual field editing using `JsonObjectCrypto`.

### Data Binding

Sensitive fields of your POJOs can be annotated with `@Encrypted`.
Let's use this class as an example:

```java
public class Employee {
  @Encrypted
  private boolean replicant;

  // alternatively you could annotate the getter or setter
  public boolean isReplicant() {
    return replicant;
  }

  public void setReplicant(boolean replicant) {
    this.replicant = replicant;
  }
}
```

Now let's create an employee record:

```java
Collection collection = cluster.bucket("myBucket")
    .defaultCollection();

Employee employee = new Employee();
employee.setReplicant(true);
collection.upsert("employee:1234", employee);
```

You can get the document as a `JsonObject` to verify the field was encrypted:

```java
JsonObject encrypted = collection.get("employee:1234")
    .contentAsObject();

System.out.println(encrypted);
```

Because `contentAsObject()` does not decrypt anything, the expected output
is something like:

```json
{
  "encrypted$replicant": {
    "alg": "AEAD_AES_256_CBC_HMAC_SHA512",
    "ciphertext": "xwcxyUyZ.....",
    "kid": "myKey"
  }
}
```

Now let's read the employee record using data binding:

```java
Employee readItBack = collection.get("employee:1234")
    .contentAs(Employee.class);

System.out.println(readItBack.isReplicant());
```

This prints `true`.

#### Using a custom ObjectMapper

The code that enables encryption/decryption during data binding is packaged
as a Jackson module called `EncryptionModule`. You can register this module
with any Jackson `ObjectMapper`.

You'll need to do this if you want to supply your own customized ObjectMapper
for the Java SDK to use when serializing documents. Here's how to configure
the cluster environment to use a a custom JSON serializer backed by your own
ObjectMapper with support for Field-Level Encryption:

```java
CryptoManager cryptoManager = createMyCryptoManager()

ObjectMapper mapper = new ObjectMapper();
mapper.registerModule(new JsonValueModule()); // for JsonObject
mapper.registerModule(new EncryptionModule(cryptoManager));

// Here you can register more modules, add mixins, enable features, etc.

ClusterEnvironment env = ClusterEnvironment.builder()
    .cryptoManager(cryptoManager)
    .jsonSerializer(JacksonJsonSerializer.create(mapper))
    .build();

Cluster cluster = Cluster.connect("localhost",
    ClusterOptions.clusterOptions("username", "password")
        .environment(env));
```

### JsonObjectCrypto

If you need more control of which fields get decrypted, or if you prefer
working with the Couchbase `JsonObject` tree model, you can use
a `JsonObjectCrypto` instance to read and write encrypted field values
of a `JsonObject`.

```java
Collection collection = cluster.bucket("myBucket").defaultCollection();

JsonObject document = JsonObject.create();
JsonObjectCrypto crypto = document.crypto(collection);

crypto.put("locationOfBuriedTreasure", "Between palm trees");

// This displays the encrypted form of the field
System.out.println(document);

collection.upsert("treasureMap", document);

JsonObject readItBack = collection.get("treasureMap").contentAsObject();
JsonObjectCrypto readItBackCrypto = crypto.withObject(readItBack);
System.out.println(readItBackCrypto.getString("locationOfBuriedTreasure"));
```

## Creating Encryption Keys

The AEAD_AES_256_CBC_HMAC_SHA512 algortihm included in this library uses
encryption keys that are 64 bytes long.

Here's an example that shows how to create a Java key store file containing
a suitable encryption key:

```java
KeyStore keyStore = KeyStore.getInstance("JCEKS");
keyStore.load(null); // initialize new empty key store

// Generate 64 random bytes
SecureRandom random = new SecureRandom();
byte[] keyBytes = new byte[64];
random.nextBytes(keyBytes);

// Add a new key called "my-key" to the key store
KeyStoreKeyring.setSecretKey(keyStore, "my-key", keyBytes,
    "protection-password".toCharArray());

// Write the key store to disk
try (OutputStream os = new FileOutputStream("MyKeystoreFile.jceks")) {
  keyStore.store(os, "integrity-password".toCharArray());
}
```

And here's how to use that file to create a `Keyring` for use with
Couchbase Field-Level Encryption:
```java
KeyStore keyStore = KeyStore.getInstance("JCEKS");
try (InputStream is = new FileInputStream("MyKeystoreFile.jceks")) {
  keyStore.load(is, "integrity-password".toCharArray());
}

KeyStoreKeyring keyring = new KeyStoreKeyring(
    keyStore, keyName -> "protection-password");
```
