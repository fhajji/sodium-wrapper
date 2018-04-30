// auth.h -- Secret Key Authentication (MAC)
//
// ISC License
// 
// Copyright (C) 2018 Farid Hajji <farid@hajji.name>
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#pragma once

#include "common.h"
#include "key.h"
#include <sodium.h>

namespace sodium {

class Auth
{
 public:

  // Some common constants for typical key and MAC sizes from <sodium.h>
  static constexpr std::size_t KEYSIZE_AUTH = sodium::KEYSIZE_AUTH;
  static constexpr std::size_t MACSIZE      = crypto_auth_BYTES;

  // Member type aliases
  using key_type = Key<KEYSIZE_AUTH>;
  
  /**
   * Create and return a Message Authentication Code (MAC) for the supplied
   * plaintext and secret key.
   *
   * The returned MAC is MACSIZE bytes long.
   **/

  bytes auth(const bytes &plaintext,
	      const key_type &key);

  /**
   * Verify MAC of plaintext using supplied secret key, returing true
   * or false whether the plaintext has been tampered with or not.
   *
   * The MAC must be MACSIZE bytes long.
   *
   * This function will throw a std::runtime_error if the size of
   * of the mac don't make sense.
   **/

  bool verify(const bytes &plaintext,
	      const bytes &mac,
	      const key_type &key);
};

} // namespace sodium
