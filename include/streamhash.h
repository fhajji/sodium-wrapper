// streamhash.h -- Generic hashing with / without key, streaming interface
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

#ifndef _S_STREAMHASH_H_
#define _S_STREAMHASH_H_

#include <sodium.h>

#include "common.h"
#include "key.h"
#include "hash.h"

#include <stdexcept>
#include <istream>
#include <ostream>

namespace Sodium {

class StreamHash {
 public:

  static constexpr std::size_t KEYSIZE      = Key::KEYSIZE_HASHKEY;
  static constexpr std::size_t KEYSIZE_MIN  = Key::KEYSIZE_HASHKEY_MIN;
  static constexpr std::size_t KEYSIZE_MAX  = Key::KEYSIZE_HASHKEY_MAX;

  static constexpr std::size_t HASHSIZE     = crypto_generichash_BYTES;
  static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
  static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;
  
  /**
   * A StreamHash will compute a keyed hash on streams of potentially
   * unlimited length using the
   * crypto_generichash_{init,update,final}() libsodium API.
   *
   * The stream will be read in a blockwise fashion with blocks
   * of size at most blocksize bytes.
   * 
   * The constructor takes a hashing key, and a desired size for the
   * hash, hashsize, for which the following preconditions must hold,
   * or else it will throw a std::runtime_error:
   *
   *   KEYSIZE_MIN   <= key.size() <= KEYSIZE_MAX,  KEYSIZE  recommended.
   *   HASHSIZE_MIN  <= hashsize   <= HASHSIZE_MAX, HASHSIZE recommended.
   **/

  StreamHash(const Key         &key,
	     const std::size_t hashsize,
	     const std::size_t blocksize) :
    key_ {key}, hashsize_ {hashsize}, blocksize_ {blocksize} {
      if (key.size() < KEYSIZE_MIN)
	throw std::runtime_error {"Sodium::StreamHash() key too small"};
      if (key.size() > KEYSIZE_MAX)
	throw std::runtime_error {"Sodium::StreamHash() key too big"};
      if (hashsize < HASHSIZE_MIN)
	throw std::runtime_error {"Sodium::StreamHash() hash size too small"};
      if (hashsize > HASHSIZE_MAX)
	throw std::runtime_error {"Sodium::StreamHash() hash size too big"};
      if (blocksize < 1)
	throw std::runtime_error {"Sodium::StreamHash() wrong blocksize"};

      crypto_generichash_init(&state_, key.data(), key.size(), hashsize);
  }

  /**
   * Keyless hashing version of the StreamHash constructor.
   *
   * Otherwise, see StreamHash() above.
   **/ 

  StreamHash(const std::size_t hashsize,
	     const std::size_t blocksize) :
    key_ {0,false}, hashsize_ {hashsize}, blocksize_ {blocksize} {
      if (hashsize < HASHSIZE_MIN)
	throw std::runtime_error {"Sodium::StreamHash() hash size too small"};
      if (hashsize > HASHSIZE_MAX)
	throw std::runtime_error {"Sodium::StreamHash() hash size too big"};
      if (blocksize < 1)
	throw std::runtime_error {"Sodium::StreamHash() wrong blocksize"};

      crypto_generichash_init(&state_, NULL, 0, hashsize);
  }

  /**
   * Hash the data provided by the std::istream istr, using the
   * hashing key provided by the constructor, or doing keyless
   * hashing. As soon as the stream reaches eof(), the hash is
   * returned, and the state is reset.
   *
   * The stream is read() blockwise, using blocks of size up to
   * blocksize_ bytes.
   *
   * It is possible to call hash() multiple times.
   *
   * hash() will throw a std::runtime_error if the istr fails.
   **/
  
  data_t hash(std::istream &istr);

  /**
   * Return-by-reference version of the hash() function above.
   * 
   * The outHash variable will contain the hash upon return.
   * 
   * The following preconditions must hold, or else hash() will
   * throw a std::runtime_error before even starting to read istr:
   *
   *   outHash.size() == hashsize (as provided by the constructor).
   * 
   * Otherwise, see also hash() above.
   **/
  
  void   hash(std::istream &istr,
	      data_t       &outHash);
  
 private:
  Key                      key_;
  std::size_t              hashsize_;
  std::size_t              blocksize_;

  crypto_generichash_state state_;
};

} // namespace Sodium

#endif // _S_STREAMHASH_H_
