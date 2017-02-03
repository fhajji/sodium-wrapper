// sodiumauth.h -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMAUTH_H_
#define _SODIUMAUTH_H_

#include "sodiumalloc.h"

#include <vector>

class SodiumAuth
{
 public:
  // data_t is unprotected memory for bytes of plaintext and MAC
  using data_t = std::vector<unsigned char>;

  // key_t is protected memory for bytes of key material
  //   * key_t memory will self-destruct/zero when out-of-scope / throws
  //   * key_t memory can be made readonly or temporarily non-accessible
  //   * key_t memory is stored in virtual pages protected by canary,
  //     guard pages, and access to those pages is granted with mprotect().
  using key_t  = std::vector<unsigned char, SodiumAlloc<unsigned char>>;

  // Create MAC using key and plaintext, returning MAC
  data_t auth(const data_t &plaintext,
	      const key_t  &key);

  // Verify MAC of plaintext using key.
  // Return true if plaintext hasn't been tampered with, false if not.
  bool verify(const data_t &plaintext,
	      const data_t &mac,
	      const key_t  &key);
};

#endif // _SODIUMAUTH_H_
