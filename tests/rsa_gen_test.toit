// Copyright (C) 2026 Toit contributors.
// Use of this source code is governed by an MIT-style license that can be
// found in the lib/LICENSE file.

import crypto.rsa

main:
  print "Generating RSA key pair (2048 bits)..."
  key := rsa.RsaKey.generate --bits=2048
  print "Key generated."

  print "Exporting keys..."
  priv-pem := key.private-key
  pub-pem := key.public-key
  print "Private key size: $priv-pem.size"
  print "Public key size: $pub-pem.size"

  print "Signing message..."
  message := "Hello, Toit RSA!"
  signature := key.sign message
  print "Signature size: $signature.size"

  print "Verifying signature with original key..."
  if key.verify message signature:
    print "Verification successful!"
  else:
    throw "Verification failed!"

  print "Parsing exported public key..."
  pub-key := rsa.RsaKey.parse-public pub-pem
  if pub-key.verify message signature:
    print "Verification with parsed public key successful!"
  else:
    throw "Verification with parsed public key failed!"

  print "Parsing exported private key..."
  priv-key := rsa.RsaKey.parse-private priv-pem
  signature2 := priv-key.sign message
  if pub-key.verify message signature2:
    print "Verification of new signature with parsed keys successful!"
  else:
    throw "Verification of new signature with parsed keys failed!"

  print "All tests passed!"
