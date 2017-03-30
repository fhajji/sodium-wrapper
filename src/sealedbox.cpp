// sealedbox.cpp -- Sealed boxes / Anonymous senders with Public-key scheme
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

#include <stdexcept>
#include "common.h"
#include "key.h"
#include "sealedbox.h"

using data_t = Sodium::data_t;

using Sodium::SealedBox;
using Sodium::Key;

data_t
SealedBox::encrypt(const data_t &plaintext,
		   const data_t &pubkey)
{
  // some sanity checks before we get started
  if (pubkey.size() != KEYSIZE_PUBKEY)
    throw std::runtime_error {"Sodium::SealedBox::encrypt() wrong pubkey size"};
  
  data_t ciphertext(SEALSIZE + plaintext.size());
  crypto_box_seal(ciphertext.data(),
		  plaintext.data(), plaintext.size(),
		  pubkey.data());
  
  return ciphertext; // by move semantics
}

data_t
SealedBox::decrypt(const data_t               &ciphertext_with_seal,
		   const Key<KEYSIZE_PRIVKEY> &privkey,
		   const data_t               &pubkey) {
  // some sanity checks before we get started
  if (pubkey.size() != KEYSIZE_PUBKEY)
    throw std::runtime_error {"Sodium::SealedBox::decrypt() wrong pubkey size"};
  if (ciphertext_with_seal.size() < SEALSIZE)
    throw std::runtime_error {"Sodium::SealedBox::decrypt() sealed ciphertext too small"};
  
  data_t decrypted(ciphertext_with_seal.size() - SEALSIZE);
  
  if (crypto_box_seal_open(decrypted.data(),
			   ciphertext_with_seal.data(),
			   ciphertext_with_seal.size(),
			   pubkey.data(),
			   privkey.data()) == -1)
    throw std::runtime_error {"Sodium::SealedBox::decrypt() can't decrypt"};
  
  return decrypted; // by move semantics
}
