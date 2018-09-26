// hashor_short.h -- Short-input hashing with key
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
#include "key.h" // keysize constants

#include <sodium.h>

namespace sodium {

template<class BT = bytes>
class hashor_short
{

  public:
    static constexpr std::size_t KEYSIZE = sodium::KEYSIZE_HASHSHORTKEY;
    static constexpr std::size_t HASHSIZE = crypto_shorthash_BYTES;

    using bytes_type = BT;
    using key_type = key<KEYSIZE>;

    // A hashor_short with a new random key
    hashor_short()
      : key_(key_type())
    {}

    /**
     * Create a short hashor with the specified key.
     *
     * Short hashing is deterministic: with the same key (hashor_short),
     * hashing a plaintext will always result in the same hash.
     **/

    // A hashor_short with a user-supplied key (copying version)
    hashor_short(const key_type& key)
      : key_(key)
    {}

    // A hashor_short with a user-supplied key (moving version)
    hashor_short(key_type&& key)
      : key_(std::move(key))
    {}

    // A copying constructor
    hashor_short(const hashor_short& other)
      : key_(other.key_)
    {}

    // A moving constructor
    hashor_short(hashor_short&& other)
      : key_(std::move(other.key_))
    {}

    // XXX copying and moving assignment operators?

    /**
     * Hash a (typically short) plaintext, using hashor_short's key_,
     * into a hash. Return the generated hash.
     *
     * This function is optimized for short plaintext(s).
     *
     * This function should _not_ be considered collision-resistant.
     *
     * Hashing the same plaintext with the same key / hashor_short
     * always results in the same hash.
     *
     * The computed and returned hash will be HASHSIZE bytes long.
     **/

    BT hash(const BT& plaintext);

    /**
     * Hash a (typically short) plaintext, using hashor_short's key_,
     * into a hash. Save the computed hash into outHash.
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

    void hash(const BT& plaintext, BT& outHash);

  private:
    key_type key_;
};

template<class BT>
BT
hashor_short<BT>::hash(const BT& plaintext)
{
    BT outHash(hashor_short<BT>::HASHSIZE);
    crypto_shorthash(reinterpret_cast<unsigned char*>(outHash.data()),
                     reinterpret_cast<const unsigned char*>(plaintext.data()),
                     plaintext.size(),
                     key_.data());
    return outHash; // using move semantics.
}

template<class BT>
void
hashor_short<BT>::hash(const BT& plaintext, BT& outHash)
{
    if (outHash.size() != hashor_short<BT>::HASHSIZE)
        throw std::runtime_error{
            "sodium::hashor_short::hash() outHash wrong size"
        };

    crypto_shorthash(reinterpret_cast<unsigned char*>(outHash.data()),
                     reinterpret_cast<const unsigned char*>(plaintext.data()),
                     plaintext.size(),
                     key_.data());
    // return outHash implicitely by reference
}

} // namespace sodium
