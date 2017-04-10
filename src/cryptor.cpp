// cryptor.cpp -- Symmetric encryption / decryption with MAC
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

#include "cryptor.h"

#include <stdexcept>

using Sodium::data_t;
using Sodium::Cryptor;

data_t
Cryptor::encrypt (const data_t     &plaintext,
		  const key_type   &key,
		  const nonce_type &nonce)
{
  // make space for MAC and encrypted message,
  // combined form, i.e. (MAC || encrypted)
  data_t ciphertext(MACSIZE + plaintext.size());
  
  // let's encrypt now!
  crypto_secretbox_easy (ciphertext.data(),
			 plaintext.data(), plaintext.size(),
			 nonce.data(),
			 key.data());

  // return the encrypted bytes
  return ciphertext;
}

data_t
Cryptor::encrypt (const data_t     &plaintext,
		  const key_type   &key,
		  const nonce_type &nonce,
		  data_t           &mac)
{
  // some sanity checks before we get started
  if (mac.size() != MACSIZE)
    throw std::runtime_error {"Sodium::Cryptor::encrypt(detached) wrong mac size"};
  
  // make space for encrypted message
  // detached form, stream cipher => same size as plaintext.
  data_t ciphertext(plaintext.size());
  
  // let's encrypt now!
  crypto_secretbox_detached (ciphertext.data(),
			     mac.data(),
			     plaintext.data(), plaintext.size(),
			     nonce.data(),
			     key.data());

  // return the encrypted bytes (mac is returned by reference)
  return ciphertext; // by move semantics
}

data_t
Cryptor::decrypt (const data_t     &ciphertext,
		  const key_type   &key,
		  const nonce_type &nonce)
{
  // some sanity checks before we get started
  if (ciphertext.size() < MACSIZE)
    throw std::runtime_error {"Sodium::Cryptor::decrypt(combined) ciphertext too small for mac"};

  // make space for decrypted buffer
  data_t decryptedtext(ciphertext.size() - MACSIZE);

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptedtext.data(),
				  ciphertext.data(), ciphertext.size(),
				  nonce.data(),
				  key.data()) != 0)
    throw std::runtime_error {"Sodium::Cryptor::decrypt(combined) can't decrypt"};

  return decryptedtext;
}

data_t
Cryptor::decrypt (const data_t     &ciphertext,
		  const data_t     &mac,
		  const key_type   &key,
		  const nonce_type &nonce)
{
  // some sanity checks before we get started
  if (mac.size() != MACSIZE)
    throw std::runtime_error {"Sodium::Cryptor::decrypt(detached) wrong mac size"};

  // make space for decrypted buffer;
  // detached mode. stream cipher => decryptedtext size == ciphertext size
  data_t decryptedtext(ciphertext.size());

  // and now decrypt!
  if (crypto_secretbox_open_detached (decryptedtext.data(),
				      ciphertext.data(),
				      mac.data(),
				      ciphertext.size(),
				      nonce.data(),
				      key.data()) != 0)
    throw std::runtime_error {"Sodium::Cryptor::decrypt(detached) can't decrypt"};

  return decryptedtext; // by move semantics
}
