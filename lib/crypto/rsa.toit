// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the lib/LICENSE file.

import .sha
import .sha1
import ..io as io

/**
Support for RSA (Rivest–Shamir–Adleman) public-key cryptography.

See https://en.wikipedia.org/wiki/RSA_cryptosystem.

RSA can be used for both encryption, and digital signatures.

# Examples

## Signing and Verifying

```
import crypto.rsa

// Assuming 'private-key' and 'public-key' are available as rsa.RsaKey.

message := "Hello world"
signature := private-key.sign message

if public-key.verify message signature:
  print "Signature is valid"
else:
  print "Signature is invalid"
```

## Alternative hashing

If you need to use other hash algorithms (e.g. SHA-1):

```
signature := private-key.sign message --hash=rsa.RsaKey.SHA-1
```
*/

class RsaKey:
  /** Produces a 20-byte digest. */
  static SHA-1 ::= 1
  /** Default. Produces a 32-byte digest. */
  static SHA-256 ::= 256
  /** Produces a 48-byte digest. */
  static SHA-384 ::= 384
  /** Produces a 64-byte digest. */
  static SHA-512 ::= 512

  /** Padding scheme PKCS#1 v1.5. */
  static PADDING-PKCS1-V15 ::= 0
  /** Padding scheme PKCS#1 v2.1 (OAEP). */
  static PADDING-OAEP-V21  ::= 1

  rsa-key_ := ?

  constructor.private_ key/io.Data password/string?="":
    rsa-key_ = rsa-parse-private-key_ resource-freeing-module_ key password

  constructor.public_ key/io.Data:
    rsa-key_ = rsa-parse-public-key_ resource-freeing-module_ key

  /**
  Parses a PKCS#1 or PKCS#8 encoded private key.
  The $key must be DER or PEM.
  The $password is optional and used for encrypted keys.
  */
  static parse-private key/io.Data --password/string?="" -> RsaKey:
    return RsaKey.private_ key password

  /**
  Parses a PKCS#1 or X.509 encoded public key.
  The $key must be DER or PEM.
  */
  static parse-public key/io.Data -> RsaKey:
    return RsaKey.public_ key

  /**
  Signs the $message with this private key.

  Hashes the $message using the specified $hash algorithm, and then signs
    the digest.

  The $hash must be one of $SHA-1, $SHA-256, $SHA-384, or $SHA-512.
  The default is $SHA-256.

  # Examples
  ```
  signature := key.sign "my message"
  ```
  */
  sign message/io.Data --hash/int=SHA-256 -> ByteArray:
    digest := compute-digest_ message hash
    return sign-digest digest --hash=hash

  /**
  Signs the $digest with this private key.

  The $digest must be the hash of the message to sign.
  The $hash is used to verify that the $digest has the correct length.
  */
  sign-digest digest/ByteArray --hash/int -> ByteArray:
    check-digest-length_ digest hash
    return rsa-sign_ rsa-key_ digest hash

  /**
  Verifies the $signature of the $message with this public key.

  Hashes the $message using the specified $hash algorithm, and then verifies
    the signature against the digest.

  The $hash must be one of $SHA-1, $SHA-256, $SHA-384, or $SHA-512.
  The default is $SHA-256.

  Returns true if the signature is valid, false otherwise.

  # Examples
  ```
  is-valid := key.verify "my message" signature
  ```
  */
  verify message/io.Data signature/ByteArray --hash/int=SHA-256 -> bool:
    digest := compute-digest_ message hash
    return verify-digest digest signature --hash=hash

  /**
  Verifies the $signature of the $digest with this public key.

  The $digest must be the hash of the message that was signed.
  The $hash is used to verify that the $digest has the correct length.
  Returns true if the signature is valid, false otherwise.
  */
  verify-digest digest/ByteArray signature/ByteArray --hash/int -> bool:
    check-digest-length_ digest hash
    return rsa-verify_ rsa-key_ digest signature hash

  /**
  Generates a new RSA key pair.
  The $bits must be one of 1024, 2048, 3072, or 4096.
  The default is 2048.
  */
  static generate --bits/int=2048 -> RsaKey:
    return RsaKey.generated_ (rsa-create-key-pair_ resource-freeing-module_ bits)

  constructor.generated_ rsa-key:
    rsa-key_ = rsa-key

  /**
  Exports the private key in PEM format.
  */
  private-key -> ByteArray:
    return rsa-export-private-key_ rsa-key_

  /**
  Exports the public key in PEM format.
  */
  public-key -> ByteArray:
    return rsa-export-public-key_ rsa-key_

  /**
  Encrypts the given $data using the public key.
  The $padding must be either $PADDING-PKCS1-V15 or $PADDING-OAEP-V21.
  Default is $PADDING-PKCS1-V15.
  The $hash is used for OAEP padding and defaults to $SHA-256.
  */
  encrypt data/ByteArray --padding/int=PADDING-PKCS1-V15 --hash/int=SHA-256 -> ByteArray:
    return rsa-encrypt_ rsa-key_ data padding hash

  /**
  Decrypts the given $data using the private key.
  The $padding must be either $PADDING-PKCS1-V15 or $PADDING-OAEP-V21.
  Default is $PADDING-PKCS1-V15.
  The $hash is used for OAEP padding and defaults to $SHA-256.
  */
  decrypt data/ByteArray --padding/int=PADDING-PKCS1-V15 --hash/int=SHA-256 -> ByteArray:
    return rsa-decrypt_ rsa-key_ data padding hash

  static check-digest-length_ digest/ByteArray hash/int:
    expected-length := 0
    if hash == SHA-256: expected-length = 32
    else if hash == SHA-1: expected-length = 20
    else if hash == SHA-384: expected-length = 48
    else if hash == SHA-512: expected-length = 64
    else: throw "INVALID_ARGUMENT"

    if digest.size != expected-length: throw "INVALID_ARGUMENT"

  static compute-digest_ message/io.Data hash/int -> ByteArray:
    if hash == SHA-256: return sha256 message
    else if hash == SHA-1: return sha1 message
    else if hash == SHA-384: return sha384 message
    else if hash == SHA-512: return sha512 message
    throw "INVALID_ARGUMENT"

rsa-parse-private-key_ group key/io.Data password/string? -> any:
  #primitive.crypto.rsa-parse-private-key:
    return io.primitive-redo-io-data_ it key: | bytes |
      rsa-parse-private-key_ group bytes password

rsa-parse-public-key_ group key/io.Data -> any:
  #primitive.crypto.rsa-parse-public-key:
    return io.primitive-redo-io-data_ it key: | bytes |
      rsa-parse-public-key_ group bytes

rsa-sign_ rsa digest/io.Data hash/int -> ByteArray:
  #primitive.crypto.rsa-sign

rsa-verify_ rsa digest/ByteArray signature/ByteArray hash/int -> bool:
  #primitive.crypto.rsa-verify

rsa-create-key-pair_ group bits/int -> any:
  #primitive.crypto.rsa-create-key-pair

rsa-export-private-key_ rsa -> ByteArray:
  #primitive.crypto.rsa-export-private-key

rsa-export-public-key_ rsa -> ByteArray:
  #primitive.crypto.rsa-export-public-key

rsa-encrypt_ rsa data padding/int hash/int -> ByteArray:
  #primitive.crypto.rsa-encrypt

rsa-decrypt_ rsa data padding/int hash/int -> ByteArray:
  #primitive.crypto.rsa-decrypt

