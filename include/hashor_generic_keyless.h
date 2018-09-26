// hashor_generic_keyless.h -- Generic hashing without key
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

#include <sodium.h>

namespace sodium {

template<class BT = bytes>
class hashor_generic_keyless
{

  public:
    static constexpr std::size_t HASHSIZE = crypto_generichash_BYTES;
    static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
    static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;

    using bytes_type = BT;

    /**
     * Hash a plaintext into a hash of the desired size of hashsize
     * bytes.  Return the generated hash.
     *
     * This is keyless generic hashing.
     *
     * Otherwise, see sodium::hashor_generic template for keyed generic hashing.
     **/

    BT hash(const BT& plaintext, const std::size_t hashsize = HASHSIZE);

    /**
     * Hash a plaintext into a hash of the size outHash.size().
     * Save the computed hash into outHash.
     *
     * This is keyless generic hashing.
     *
     * Otherwise, see sodium::hashor_generic template for keyed generic hashing.
     **/

    void hash(const BT& plaintext, BT& outHash);
};

template<class BT>
BT
hashor_generic_keyless<BT>::hash(const BT& plaintext,
                                 const std::size_t hashsize)
{
    // some sanity checks before we start
    if (hashsize < hashor_generic_keyless<BT>::HASHSIZE_MIN)
        throw std::runtime_error{
            "sodium::hashor_generic_keyless::hash() hash size too small"
        };
    if (hashsize > hashor_generic_keyless<BT>::HASHSIZE_MAX)
        throw std::runtime_error{
            "sodium::hashor_generic_keyless::hash() hash size too big"
        };

    // make space for hash
    BT outHash(hashsize);

    // now compute the hash!
    crypto_generichash(reinterpret_cast<unsigned char*>(outHash.data()),
                       outHash.size(),
                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                       plaintext.size(),
                       NULL,
                       0); // keyless hashing

    // return hash
    return outHash; // using move semantics
}

template<class BT>
void
hashor_generic_keyless<BT>::hash(const BT& plaintext, BT& outHash)
{
    // some sanity checks before we start
    if (outHash.size() < hashor_generic_keyless<BT>::HASHSIZE_MIN)
        throw std::runtime_error{
            "sodium::hashor_generic_keyless::hash() hash size too small"
        };
    if (outHash.size() > hashor_generic_keyless<BT>::HASHSIZE_MAX)
        throw std::runtime_error{
            "sodium::hashor_generic_keyless::hash() hash size too big"
        };

    // now compute the hash!
    crypto_generichash(reinterpret_cast<unsigned char*>(outHash.data()),
                       outHash.size(),
                       reinterpret_cast<const unsigned char*>(plaintext.data()),
                       plaintext.size(),
                       NULL,
                       0); // keyless hashing

    // hash is returned implicitely in outHash by reference.
}

} // namespace sodium