// cryptormultipk.cpp -- PK enc/dec with MAC, with precalculated shared key
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

#include "cryptormultipk.h"
#include "common.h"

#include <stdexcept>
#include <sodium.h>

using bytes = sodium::bytes;
using sodium::CryptorMultiPK;

void
CryptorMultiPK::set_shared_key (const private_key_type &private_key,
				const public_key_type       &public_key)
{
  // some sanity checks before we get started
  if (public_key.size() != KEYSIZE_PUBLIC_KEY)
    throw std::runtime_error {"sodium::CryptorMultiPK::initkey() wrong public_key size"};
    
  // now, ready to go
  shared_key_.readwrite();
  if (crypto_box_beforenm(shared_key_.setdata(),
			  public_key.data(),
			  private_key.data()) == -1) {
    shared_key_ready_ = false; // XXX: undefined?
    throw std::runtime_error {"sodium::CryptorMultiPK::initkey() crypto_box_beforenm() -1"};
  }
  shared_key_.readonly();
  shared_key_ready_ = true;
}

bytes
CryptorMultiPK::encrypt(const bytes     &plaintext,
			const nonce_type &nonce)
{
  // some sanity checks before we start
  if (! shared_key_ready_)
    throw std::runtime_error {"sodium::CryptorMultiPK::encrypt() shared key not ready"};

  // make space for ciphertext, i.e. for (MAC || encrypted)
  bytes ciphertext(MACSIZE + plaintext.size());

  // and now, encrypt!
  if (crypto_box_easy_afternm(ciphertext.data(),
			      plaintext.data(), plaintext.size(),
			      nonce.data(),
			      shared_key_.data()) == -1)
    throw std::runtime_error {"sodium::CryptorMultiPK::encrypt() crypto_box_easy_afternm() -1"};

  return ciphertext; // move semantics
}

bytes
CryptorMultiPK::decrypt(const bytes &ciphertext_with_mac,
			const nonce_type &nonce)
{
  // some sanity checks before we start
  if (ciphertext_with_mac.size() < MACSIZE)
    throw std::runtime_error {"sodium::CryptorMultiPK::decrypt() ciphertext too small for even for MAC"};
  if (! shared_key_ready_)
    throw std::runtime_error {"sodium::CryptorMultiPK::decrypt() shared key not ready"};

  // make space for decrypted text
  bytes decrypted(ciphertext_with_mac.size() - MACSIZE);

  // and now, decrypt!
  if (crypto_box_open_easy_afternm(decrypted.data(),
				   ciphertext_with_mac.data(),
				   ciphertext_with_mac.size(),
				   nonce.data(),
				   shared_key_.data()) == -1)
    throw std::runtime_error {"sodium::CryptorMultiPK::decrypt() decryption failed"};

  return decrypted; // move semantics
}
