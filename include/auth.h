// auth.h -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _S_AUTH_H_
#define _S_AUTH_H_

#include "common.h"
#include "key.h"
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

  data_t auth(const data_t &plaintext,
	      const Key    &key);

  /**
   * Verify MAC of plaintext using supplied secret key, returing true
   * or false whether the plaintext has been tampered with or not.
   *
   * This function will throw a std::runtime_error if the sizes of
   * the key or the mac don't make sense.
   **/

  bool verify(const data_t &plaintext,
	      const data_t &mac,
	      const Key    &key);
};

} // namespace Sodium
 
#endif // _S_AUTH_H_
