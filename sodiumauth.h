// sodiumauth.h -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMAUTH_H_
#define _SODIUMAUTH_H_

#include "sodiumcommon.h"
#include "sodiumkey.h"
#include <vector>

namespace Sodium {

class Auth
{
 public:

  /**
   * Create and return a Message Authentication Code (MAC) for the supplied
   * plaintext and secret key.
   *
   * This function will throw a std::runtime_error if the length of
   * the key doesn't make sense.
   **/

  data_t auth(const data_t       &plaintext,
	      const Sodium::Key  &key);

  /**
   * Verify MAC of plaintext using supplied secret key, returing true
   * or false whether the plaintext has been tampered with or not.
   *
   * This function will throw a std::runtime_error if the sizes of
   * the key or the mac don't make sense.
   **/

  bool verify(const data_t      &plaintext,
	      const data_t      &mac,
	      const Sodium::Key &key);
};

} // namespace Sodium
 
#endif // _SODIUMAUTH_H_
