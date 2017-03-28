// hash.cpp -- Generic hashing with / without key
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

#include "common.h"
#include "key.h"
#include "hash.h"

#include <sodium.h>

using data_t = Sodium::data_t;

using Sodium::Key;
using Sodium::Hash;

data_t
Hash::hash (const data_t &plaintext,
	    const Key    &key,
	    const std::size_t hashsize)
{
  // some sanity checks before we start
  if (key.size() < Hash::KEYSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() key size too small"};
  if (key.size() > Hash::KEYSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() key size too big"};
  if (hashsize < Hash::HASHSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too small"};
  if (hashsize > Hash::HASHSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too big"};

  // make space for hash
  data_t outHash(hashsize);

  // now compute the hash!
  crypto_generichash(outHash.data(), outHash.size(),
		     plaintext.data(), plaintext.size(),
		     key.data(), key.size());

  // return hash
  return outHash; // using move semantics
}

data_t
Hash::hash (const data_t &plaintext,
	    const std::size_t hashsize)
{
  // some sanity checks before we start
  if (hashsize < Hash::HASHSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too small"};
  if (hashsize > Hash::HASHSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too big"};

  // make space for hash
  data_t outHash(hashsize);

  // now compute the hash!
  crypto_generichash(outHash.data(), outHash.size(),
		     plaintext.data(), plaintext.size(),
		     NULL, 0); // keyless hashing
  
  // return hash
  return outHash; // using move semantics
}

void
Hash::hash (const data_t &plaintext,
	    const Key    &key,
	    data_t       &outHash)
{
  // some sanity checks before we start
  if (key.size() < Hash::KEYSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() key size too small"};
  if (key.size() > Hash::KEYSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() key size too big"};
  if (outHash.size() < Hash::HASHSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too small"};
  if (outHash.size() > Hash::HASHSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too big"};

  // now compute the hash!
  crypto_generichash(outHash.data(), outHash.size(),
		     plaintext.data(), plaintext.size(),
		     key.data(), key.size());

  // hash is returned implicitely in outHash by reference.
}

void
Hash::hash (const data_t &plaintext,
	    data_t       &outHash)
{
  // some sanity checks before we start
  if (outHash.size() < Hash::HASHSIZE_MIN)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too small"};
  if (outHash.size() > Hash::HASHSIZE_MAX)
    throw std::runtime_error {"Sodium::Hash::hash() hash size too big"};

  // now compute the hash!
  crypto_generichash(outHash.data(), outHash.size(),
		     plaintext.data(), plaintext.size(),
		     NULL, 0); // keyless hashing
  
  // hash is returned implicitely in outHash by reference.
}
