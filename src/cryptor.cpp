// cryptor.cpp -- Symmetric encryption / decryption with MAC
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

#include "cryptor.h"
#include "nonce.h"
#include "key.h"

#include <stdexcept>

using Sodium::data_t;
using Sodium::Cryptor;
using Sodium::Key;
using Sodium::Nonce;

data_t
Cryptor::encrypt (const data_t     &plaintext,
		  const Key        &key,
		  const Nonce<NSZ> &nonce)
{
  // get the sizes
  const std::size_t ciphertext_size =
    crypto_secretbox_MACBYTES + plaintext.size();
  const std::size_t key_size        = Key::KEYSIZE_SECRETBOX;
  const std::size_t nonce_size      = Sodium::NONCESIZE_SECRETBOX;
  
  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"Sodium::Cryptor::encrypt() wrong key size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"Sodium::Cryptor::encrypt() wrong nonce size"};
  
  // make space for MAC and encrypted message
  data_t ciphertext(ciphertext_size);
  
  // let's encrypt now!
  crypto_secretbox_easy (ciphertext.data(),
			 plaintext.data(), plaintext.size(),
			 nonce.data(),
			 key.data());

  // return the encrypted bytes
  return ciphertext;
}

data_t
Cryptor::decrypt (const data_t     &ciphertext,
		  const Key        &key,
		  const Nonce<NSZ> &nonce)
{
  // get the sizes
  const std::size_t key_size        = key.size();
  const std::size_t nonce_size      = nonce.size();
  const std::size_t ciphertext_size = ciphertext.size();
  const std::size_t plaintext_size  =
    ciphertext_size - crypto_secretbox_MACBYTES;
  
  // some sanity checks before we get started
  if (key_size != Key::KEYSIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() wrong nonce size"};
  if (ciphertext_size < crypto_secretbox_MACBYTES)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() ciphertext too small for mac"};

  // make space for decrypted buffer
  data_t decryptedtext(plaintext_size);

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptedtext.data(),
				  ciphertext.data(), ciphertext.size(),
				  nonce.data(),
				  key.data()) != 0)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() can't decrypt (sodium test)"};

  return decryptedtext;
}
