// sodiumauth.h -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMAUTH_H_
#define _SODIUMAUTH_H_

#include "sodiumkey.h"
#include <vector>

namespace Sodium {

class Auth
{
 public:
  // data_t is unprotected memory for bytes of plaintext and MAC
  using data_t = std::vector<unsigned char>;

  // Create MAC using key and plaintext, returning MAC
  data_t auth(const data_t       &plaintext,
	      const Sodium::Key  &key);

  // Verify MAC of plaintext using key.
  // Return true if plaintext hasn't been tampered with, false if not.
  bool verify(const data_t      &plaintext,
	      const data_t      &mac,
	      const Sodium::Key &key);
};

} // namespace Sodium
 
#endif // _SODIUMAUTH_H_
