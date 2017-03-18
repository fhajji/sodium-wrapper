// cryptormultipk.cpp -- PK enc/dec with MAC, with precalculated shared key
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

#include "cryptormultipk.h"
#include "key.h"
#include "nonce.h"
#include "common.h"

#include <stdexcept>
#include <sodium.h>

using Sodium::data_t;
using Sodium::CryptorMultiPK;
using Sodium::Key;
using Sodium::Nonce;

void
CryptorMultiPK::set_shared_key (const Key    &privkey,
				const data_t &pubkey)
{
  // some sanity checks before we get started
  if (pubkey.size() != KEYSIZE_PUBKEY)
    throw std::runtime_error {"Sodium::CryptorMultiPK::initkey() wrong pubkey size"};
  
  if (privkey.size() != KEYSIZE_PRIVKEY)
    throw std::runtime_error {"Sodium::CryptorMultiPK::initkey() wrong privkey size"};
  
  // now, ready to go
  shared_key_.readwrite();
  if (crypto_box_beforenm(shared_key_.setdata(),
			  pubkey.data(),
			  privkey.data()) == -1) {
    shared_key_ready_ = false; // XXX: undefined?
    throw std::runtime_error {"Sodium::CryptorMultiPK::initkey() crypto_box_beforenm() -1"};
  }
  shared_key_.readonly();
  shared_key_ready_ = true;
}

data_t
CryptorMultiPK::encrypt(const data_t       &plaintext,
			const Nonce<NSZPK> &nonce)
{
  // some sanity checks before we start
  if (nonce.size() != NSZPK)
    throw std::runtime_error {"CryptorMultiPK::encrypt() wrong nonce size"};
  if (! shared_key_ready_)
    throw std::runtime_error {"CryptorMultiPK::encrypt() shared key not ready"};

  // make space for MAC + ciphertext
  data_t ciphertext(plaintext.size() + MACSIZE);

  // and now, encrypt!
  if (crypto_box_easy_afternm(ciphertext.data(),
			      plaintext.data(), plaintext.size(),
			      nonce.data(),
			      shared_key_.data()) == -1)
    throw std::runtime_error {"CryptorMultiPK::encrypt() crypto_box_easy_afternm() -1"};

  return ciphertext; // move semantics
}

data_t
CryptorMultiPK::decrypt(const data_t       &ciphertext_with_mac,
			const Nonce<NSZPK> &nonce)
{
  // some sanity checks before we start
  if (nonce.size() != NSZPK)
    throw std::runtime_error {"CryptorMultiPK::decrypt() wrong nonce size"};
  if (ciphertext_with_mac.size() < MACSIZE)
    throw std::runtime_error {"CryptorMultiPK::decrypt() ciphertext too small for even for MAC"};
  if (! shared_key_ready_)
    throw std::runtime_error {"CryptorMultiPK::decrypt() shared key not ready"};

  // make space for decrypted text
  data_t decrypted(ciphertext_with_mac.size() - MACSIZE);

  // and now, decrypt!
  if (crypto_box_open_easy_afternm(decrypted.data(),
				   ciphertext_with_mac.data(),
				   ciphertext_with_mac.size(),
				   nonce.data(),
				   shared_key_.data()) == -1)
    throw std::runtime_error {"CryptorMultiPK::decrypt() decryption failed"};

  return decrypted; // move semantics
}
