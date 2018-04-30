// streamhash.cpp -- Generic hashing with / without key, streaming interface
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

#include <istream>

#include "common.h"
#include "streamhash.h"

#include <sodium.h>

using bytes = sodium::bytes;
using sodium::StreamHash;

bytes
StreamHash::hash(std::istream &istr)
{
  bytes plaintext(blocksize_, '\0');
  bytes outHash(hashsize_);

  if (key_.size() != 0)
    crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
  else
    crypto_generichash_init(&state_, NULL, 0, hashsize_); // keyless
  
  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    // read a whole block of size blocksize_

    crypto_generichash_update(&state_, plaintext.data(), plaintext.size());
  }

  // check to see if we've read a final partial chunk
  std::size_t s = static_cast<std::size_t>(istr.gcount());
  if (s != 0) {
    if (s != plaintext.size())
      plaintext.resize(s);

    crypto_generichash_update(&state_, plaintext.data(), plaintext.size());
  }

  // we're done reading all chunks.
  crypto_generichash_final(&state_, outHash.data(), outHash.size());

  // reset state_, so can call hash() again
  if (key_.size() != 0)
    crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
  else
    crypto_generichash_init(&state_, NULL, 0, hashsize_); // keyless

  // return computed hash
  return outHash; // with move semantics
}

void
StreamHash::hash(std::istream &istr,
		 bytes       &outHash)
{
  if (outHash.size() != hashsize_)
    throw std::runtime_error {"sodium::StreamHash::hash() wrong outHash size"};

  bytes plaintext(blocksize_, '\0');

  if (key_.size() != 0)
    crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
  else
    crypto_generichash_init(&state_, NULL, 0, hashsize_); // keyless
  
  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    // read a whole block of size blocksize_

    crypto_generichash_update(&state_, plaintext.data(), plaintext.size());
  }

  // check to see if we've read a final partial chunk
  std::size_t s = static_cast<std::size_t>(istr.gcount());
  if (s != 0) {
    if (s != plaintext.size())
      plaintext.resize(s);

    crypto_generichash_update(&state_, plaintext.data(), plaintext.size());
  }

  // we're done reading all chunks.
  crypto_generichash_final(&state_, outHash.data(), outHash.size());

  // reset state_, so can call hash() again
  if (key_.size() != 0)
    crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
  else
    crypto_generichash_init(&state_, NULL, 0, hashsize_); // keyless
    
  // returning outHash implicitely by reference.
}