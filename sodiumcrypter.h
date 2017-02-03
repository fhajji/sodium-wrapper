// sodiumcrypter.h -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCRYPTER_H_
#define _SODIUMCRYPTER_H_

#include "key.h"

#include <vector>
#include <string>

class SodiumCrypter
{
 public:
  // data_t is unprotected memory for bytes of plaintext, ciphertext and nonces
  using data_t = std::vector<unsigned char>;

  // Encrypt plaintext with MAC using key and nonce, returning ciphertext.
  data_t encrypt(const data_t      &plaintext,
		 const Sodium::Key &key,
		 const data_t      &nonce);

  // Decrypt ciphertext using key and nonce, returning decrypted text
  // or throwing std::runtime_error if ciphertext was corrupted.
  data_t decrypt(const data_t      &ciphertext,
		 const Sodium::Key &key,
		 const data_t      &nonce);

  // Convert ciphertext bytes into a string of hexadecimal symbols.
  std::string tohex(const data_t &ciphertext);
};

#endif // _SODIUMCRYPTER_H_
