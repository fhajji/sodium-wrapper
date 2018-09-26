// hashor_generic.h -- Generic hashing with key
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
#include "keyvar.h"

#include <sodium.h>

namespace sodium {

template<class BT = bytes>
class hashor_generic
{

  public:
    static constexpr std::size_t KEYSIZE = sodium::KEYSIZE_HASHKEY;
    static constexpr std::size_t KEYSIZE_MIN = sodium::KEYSIZE_HASHKEY_MIN;
    static constexpr std::size_t KEYSIZE_MAX = sodium::KEYSIZE_HASHKEY_MAX;
    static constexpr std::size_t HASHSIZE = crypto_generichash_BYTES;
    static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
    static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;

    using bytes_type = BT;
    using key_type = keyvar<>;

    // A hashor_generic with a new random key of default length
    hashor_generic()
      : key_(key_type(KEYSIZE))
    {}

    /**
     * Create a generic hashor with the specified key.
     *
     * The key must satisfy the following requirement:
     *
     *   KEYSIZE_MIN <= key.size() <= KEYSIZE_MAX, KEYSIZE  recommended.
     *
     * The constructor will throw a std::runtime_error if not.
     *
     * Generic hashing is deterministic: with the same key (hashor_generic),
     * and the same desired hash size, hashing a plaintext will
     * always result in the same hash.
     **/

    // A hashor_generic with a user-supplied key (copying version)
    hashor_generic(const key_type& key)
      : key_(key)
    {
        // some sanity checks before we start

        if (key_.size() < hashor_generic<BT>::KEYSIZE_MIN)
            throw std::runtime_error{
                "sodium::hashor_generic key size too small"
            };
        if (key_.size() > hashor_generic<BT>::KEYSIZE_MAX)
            throw std::runtime_error{
                "sodium::hashor_generic key size too big"
            };
    }

    // A hashor_generic with a user-supplied key (moving version)
    hashor_generic(key_type&& key)
      : key_(std::move(key))
    {
        // some sanity checks before we start

        if (key_.size() < hashor_generic<BT>::KEYSIZE_MIN)
            throw std::runtime_error{
                "sodium::hashor_generic key size too small"
            };
        if (key_.size() > hashor_generic<BT>::KEYSIZE_MAX)
            throw std::runtime_error{
                "sodium::hashor_generic key size too big"
            };
    }

    // A copying constructor
    hashor_generic(const hashor_generic& other)
      : key_(other.key_)
    {
        // other key has already been sanity-checked for length
    }

    // A moving constructor
    hashor_generic(hashor_generic&& other)
      : key_(std::move(other.key_))
    {
        // other key has already been sanity-checked for length
    }

    // XXX copying and moving assignment operators?

    /**
     * Hash a plaintext, using the provided key, into a hash of the desired
     * size of hashsize bytes. Return the generated hash.
     *
     * The following precondition must hold, or else hash() will throw
     * a std::runtime_error:
     *
     *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, with HASHSIZE recommended.
     *
     * The same plaintext with the same key and same desired hashsize
     * will always result in same hash. All things being equal, changing
     * the key will very likely result in a different hash.
     *
     * The computed and returned hash will be hashsize bytes long.
     **/

    BT hash(const BT& plaintext, const std::size_t hashsize = HASHSIZE);

    /**
     * Hash a plaintext, using the provided key, into a hash of the
     * size outHash.size(). Save the computed hash into outHash.
     *
     * The following precondition must hold, or else hash() will throw
     * a std::runtime_error:
     *
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

    void hash(const BT& plaintext, BT& outHash);

  private:
    key_type key_;
};

template<class BT>
BT
hashor_generic<BT>::hash(const BT& plaintext, const std::size_t hashsize)
{
    // some sanity checks before we start
    if (hashsize < hashor_generic<BT>::HASHSIZE_MIN)
        throw std::runtime_error{
            "sodium::hashor_generic::hash() hash size too small"
        };
    if (hashsize > hashor_generic<BT>::HASHSIZE_MAX)
        throw std::runtime_error{
            "sodium::hashor_generic::hash() hash size too big"
        };

    // make space for hash
    BT outHash(hashsize);

    // now compute the hash!
    crypto_generichash(reinterpret_cast<unsigned char*>(outHash.data()),
                       outHash.size(),
                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                       plaintext.size(),
                       key_.data(),
                       key_.size());

    // return hash
    return outHash; // using move semantics
}

template<class BT>
void
hashor_generic<BT>::hash(const BT& plaintext, BT& outHash)
{
    // some sanity checks before we start
    if (outHash.size() < hashor_generic<BT>::HASHSIZE_MIN)
        throw std::runtime_error{
            "sodium::hashor_generic::hash() hash size too small"
        };
    if (outHash.size() > hashor_generic<BT>::HASHSIZE_MAX)
        throw std::runtime_error{
            "sodium::hashor_generic::hash() hash size too big"
        };

    // now compute the hash!
    crypto_generichash(reinterpret_cast<unsigned char*>(outHash.data()),
                       outHash.size(),
                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                       plaintext.size(),
                       key_.data(),
                       key_.size());

    // hash is returned implicitely in outHash by reference.
}

} // namespace sodium