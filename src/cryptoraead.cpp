// cryptoraead.cpp -- Authenticated Encryption with Added Data
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "cryptoraead.h"
#include "key.h"
#include "nonce.h"

#include <stdexcept>

using Sodium::data_t;
using Sodium::CryptorAEAD;
using Sodium::Key;
using Sodium::Nonce;

data_t
CryptorAEAD::encrypt (const data_t      &header,
		      const data_t      &plaintext,
		      const Key         &key,
		      const Nonce<NSZA> &nonce)
{
  // get the sizes
  const std::size_t ciphertext_size =
    plaintext.size() + CryptorAEAD::MACSIZE;
  const std::size_t key_size        = Key::KEYSIZE_AEAD;
  const std::size_t nonce_size      = Sodium::NONCESIZE_AEAD;

  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"Sodium::CryptorAEAD::encrypt() wrong key size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"Sodium::CryptorAEAD::encrypt() wrong nonce size"};

  // make space for MAC and encrypted message
  data_t ciphertext(ciphertext_size);

  // so many bytes will really be written into output buffer
  unsigned long long clen;
  
  // let's encrypt now!
  crypto_aead_chacha20poly1305_encrypt (ciphertext.data(), &clen,
					plaintext.data(), plaintext.size(),
					(header.empty() ? nullptr : header.data()), header.size(),
					NULL /* nsec */,
					nonce.data(),
					key.data());
  ciphertext.resize(clen);

  return ciphertext;
}

data_t
CryptorAEAD::decrypt (const data_t      &header,
		      const data_t      &ciphertext_with_mac,
		      const Key         &key,
		      const Nonce<NSZA> &nonce)
{
  // get the sizes
  const std::size_t key_size   = key.size();
  const std::size_t nonce_size = nonce.size();
  const std::size_t plaintext_size =
    ciphertext_with_mac.size() - CryptorAEAD::MACSIZE;

  // some sanity checks before we get started
  if (key_size != Key::KEYSIZE_AEAD)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_AEAD)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() wrong nonce size"};
  if (ciphertext_with_mac.size() < CryptorAEAD::MACSIZE)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() ciphertext length too small for a tag"};

  // make space for decrypted buffer
  data_t plaintext(plaintext_size);

  // how many bytes we decrypt
  unsigned long long mlen;
  
  // and now decrypt!
  if (crypto_aead_chacha20poly1305_decrypt (plaintext.data(), &mlen,
					    nullptr /* nsec */,
					    ciphertext_with_mac.data(), ciphertext_with_mac.size(),
					    (header.empty() ? nullptr : header.data()), header.size(),
					    nonce.data(),
					    key.data()) == -1)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() can't decrypt or message/tag corrupt"};
  plaintext.resize(mlen);

  return plaintext;
}
