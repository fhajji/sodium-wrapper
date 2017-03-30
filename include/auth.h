// auth.h -- Secret Key Authentication (MAC)
//
// ISC License
// 
// Copyright (c) 2017 Farid Hajji <farid@hajji.name>
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

#ifndef _S_AUTH_H_
#define _S_AUTH_H_

#include <sodium.h>
#include "common.h"
#include "key.h"

namespace Sodium {

class Auth
{
 public:

  // Some common constants for typical key and MAC sizes from <sodium.h>
  static constexpr std::size_t KEYSIZE_AUTH = Sodium::KEYSIZE_AUTH;
  static constexpr std::size_t MACSIZE      = crypto_auth_BYTES;

  /**
   * Create and return a Message Authentication Code (MAC) for the supplied
   * plaintext and secret key.
   *
   * The returned MAC is MACSIZE bytes long.
   **/

  data_t auth(const data_t            &plaintext,
	      const Key<KEYSIZE_AUTH> &key);

  /**
   * Verify MAC of plaintext using supplied secret key, returing true
   * or false whether the plaintext has been tampered with or not.
   *
   * The MAC must be MACSIZE bytes long.
   *
   * This function will throw a std::runtime_error if the size of
   * of the mac don't make sense.
   **/

  bool verify(const data_t            &plaintext,
	      const data_t            &mac,
	      const Key<KEYSIZE_AUTH> &key);
};

} // namespace Sodium
 
#endif // _S_AUTH_H_
