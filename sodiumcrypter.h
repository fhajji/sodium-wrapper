// sodiumcrypter.h -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCRYPTER_H_
#define _SODIUMCRYPTER_H_

#include "sodiumalloc.h"

#include <vector>
#include <string>

class SodiumCrypter
{
 public:
  // data_t is unprotected memory for bytes of plaintext, cyphertext and nonces
  using data_t = std::vector<unsigned char>;

  // key_t is protected memory for bytes of key material
  //   * key_t memory will self-destruct/zero when out-of-scope / throws
  //   * key_t memory can be made readonly or temporarily non-accessible
  //   * key_t memory is stored in virtual pages protected by canary
  //     and access to those pages is granted with mprotect().
  using key_t  = std::vector<unsigned char, SodiumAlloc<unsigned char>>;

  // Encrypt plaintext with MAC using key and nonce, returning cyphertext.
  data_t encrypt(const data_t &plaintext,
		 const key_t  &key,
		 const data_t &nonce);

  // Decrypt cyphertext using key and nonce, returning decrypted text
  // or throwing std::runtime_error if cyphertext was corrupted.
  data_t decrypt(const data_t &cyphertext,
		 const key_t  &key,
		 const data_t &nonce);

  // Convert cyphertext bytes into a string of hexadecimal symbols.
  std::string tohex(const data_t &cyphertext);
};

#endif // _SODIUMCRYPTER_H_
