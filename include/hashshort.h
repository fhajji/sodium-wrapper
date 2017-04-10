// hashshort.h -- Short-input hashing with / without key
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

#ifndef _S_HASHSHORT_H_
#define _S_HASHSHORT_H_

#include "common.h"
#include "key.h"     // keysize constants

#include <sodium.h>

namespace Sodium {

class HashShort {

 public:
  static constexpr std::size_t KEYSIZE      = Sodium::KEYSIZE_HASHSHORTKEY;
  static constexpr std::size_t HASHSIZE     = crypto_shorthash_BYTES;

  using key_type = Key<KEYSIZE>;
  
  /**
   * Hash a (typically short) plaintext, using the provided key, into
   * a hash. Return the generated hash.
   *
   * This function is optimized for short plaintext(s).
   *
   * This function should _not_ be considered collision-resistant.
   *
   * Hashing the same plaintext with the same key always results in
   * the same hash.
   * 
   * The computed and returned hash will be HASHSIZE bytes long.
   **/
  
  data_t hash(const data_t   &plaintext,
	      const key_type &key) {
    data_t outHash(HASHSIZE);
    crypto_shorthash(outHash.data(),
		     plaintext.data(), plaintext.size(),
		     key.data());
    return outHash; // using move semantics.
  }

    
  /**
   * Hash a (typically short) plaintext, using the provided key, into
   * a hash. Save the computed hash into outHash.
   * 
   * This function is optimized for short plaintext(s).
   *
   * The following precondition must hold, or else hash() will throw
   * a std::runtime_error:
   * 
   *   outHash.size() == HASHSIZE.
   * 
   * Note that outHash MUST already have been pre-allocated with
   * enough space to hold the hash bytes.
   * 
   * This function should _not_ be considered collision-resistant.
   * 
   * Hashing the same plaintext with the same key always results in
   * the same hash.
   **/

  void   hash(const data_t   &plaintext,
	      const key_type &key,
	      data_t         &outHash) {
    if (outHash.size() != HASHSIZE)
      throw std::runtime_error {"Sodium::HashShort::hash() outHash wrong size"};
    crypto_shorthash(outHash.data(),
		     plaintext.data(), plaintext.size(),
		     key.data());
    // return outHash implicitely by reference
  }

};

} // namespace Sodium
 
#endif // _S_HASHSHORT_H_
