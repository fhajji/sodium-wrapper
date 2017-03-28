// hash.h -- Generic hashing with / without key
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

#ifndef _S_HASH_H_
#define _S_HASH_H_

#include "common.h"
#include "key.h"

#include <sodium.h>

namespace Sodium {

class Hash {

 public:
  static constexpr std::size_t KEYSIZE      = Key::KEYSIZE_HASHKEY;
  static constexpr std::size_t KEYSIZE_MIN  = Key::KEYSIZE_HASHKEY_MIN;
  static constexpr std::size_t KEYSIZE_MAX  = Key::KEYSIZE_HASHKEY_MAX;
  static constexpr std::size_t HASHSIZE     = crypto_generichash_BYTES;
  static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
  static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;

  /**
   * Hash a plaintext, using the provided key, into a hash of the desired
   * size of hashsize bytes. Return the generated hash.
   *
   * The following preconditions must hold, or else hash() will throw
   * a std::runtime_error:
   * 
   *   KEYSIZE_MIN  <= key.size() <= KEYSIZE_MAX,  with KEYSIZE  recommended.
   *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, with HASHSIZE recommended.
   *
   * The same plaintext with the same key and same desired hashsize
   * will always result in same hash. All things being equal, changing
   * the key will very likely result in a different hash.
   *
   * The computed and returned hash will be hashsize bytes long.
   **/
  
  data_t hash(const data_t       &plaintext,
	      const Key          &key,
	      const std::size_t  hashsize=HASHSIZE);

  /**
   * Hash a plaintext into a hash of the desired size of hashsize
   * bytes.  Return the generated hash.
   *
   * This is a keyless hashing version of the hash() function.
   *
   * Otherwise, see hash() above.
   **/

  data_t hash(const data_t &plaintext,
	      const std::size_t hashsize=HASHSIZE);
  
  
  /**
   * Hash a plaintext, using the provided key, into a hash of the
   * size outHash.size(). Save the computed hash into outHash.
   *
   * Tthe following preconditions must hold, or else hash() will throw
   * a std::runtime_error:
   * 
   *   KEYSIZE_MIN  <= key.size()     <= KEYSIZE_MAX,  KEYSIZE  recommended.
   *   HASHSIZE_MIN <= outHash.size() <= HASHSIZE_MAX, HASHSIZE recommended.
   * 
   * Note that outHash MUST already have been pre-allocated with
   * enough space to hold the hash bytes, and that outHash.size() upon
   * entry will indicate the number of desired hash bytes to compute.
   * 
   * The same plaintext with the same key and same desired hashsize
   * will always result in same hash. All things being equal, changing
   * the key will very likely result in a different hash.
   **/

  void   hash(const data_t &plaintext,
	      const Key    &key,
	      data_t       &outHash);

  /**
   * Hash a plaintext into a hash of the size outHash.size().
   * Save the computed hash into outHash.
   * 
   * This is a keyless hashing version of the hash() function.
   * 
   * Otherwise, see hash() above.
   **/
  
  void   hash(const data_t &plaintext,
	      data_t       &outHash);
  
};

} // namespace Sodium
 
#endif // _S_HASH_H_
