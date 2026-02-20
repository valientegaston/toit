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
  print "Private key:\n$priv-pem.to-string"
  print "Public key:\n$pub-pem.to-string"

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
  print "Verification of new signature with parsed keys successful!"

  print "Testing encryption/decryption..."
  original-token := "MySecretToken123"
  print "Original token: $original-token"
  
  encrypted := pub-key.encrypt original-token.to-byte-array
  print "Encrypted token size: $encrypted.size"
  
  decrypted := priv-key.decrypt encrypted
  decrypted-str := decrypted.to-string
  print "Decrypted token: $decrypted-str"
  
  if original-token == decrypted-str:
    print "Encryption/Decryption successful!"
  else:
    throw "Encryption/Decryption failed!"

  print "Testing encryption/decryption (OAEP SHA256)..."
  oaep-encrypted := pub-key.encrypt original-token.to-byte-array --padding=rsa.RsaKey.PADDING-OAEP-V21 --hash=rsa.RsaKey.SHA-256
  print "Encrypted (OAEP) token size: $oaep-encrypted.size"
  
  oaep-decrypted := priv-key.decrypt oaep-encrypted --padding=rsa.RsaKey.PADDING-OAEP-V21 --hash=rsa.RsaKey.SHA-256
  oaep-decrypted-str := oaep-decrypted.to-string
  print "Decrypted (OAEP) token: $oaep-decrypted-str"
  
  if original-token == oaep-decrypted-str:
    print "OAEP Encryption/Decryption successful!"
  else:
    throw "OAEP Encryption/Decryption failed!"

  print "All tests passed!"
