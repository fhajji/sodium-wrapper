// cryptorpk.cpp -- Public-key encryption / decryption with MAC
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

#include "cryptorpk.h"
#include "key.h"
#include "nonce.h"
#include "common.h"

#include <stdexcept>
#include <sodium.h>

using Sodium::data_t;
using Sodium::CryptorPK;
using Sodium::Key;
using Sodium::KeyPair;
using Sodium::Nonce;

data_t
CryptorPK::encrypt (const data_t       &plaintext,
		    const data_t       &pubkey,
		    const Key          &privkey,
		    const Nonce<NSZPK> &nonce)
{
  // some sanity checks before we get started
  if (pubkey.size() != CryptorPK::KEYSIZE_PUBKEY)
    throw std::runtime_error {"Sodium::CryptorPK::encrypt() wrong pubkey size"};
  if (privkey.size() != CryptorPK::KEYSIZE_PRIVKEY)
    throw std::runtime_error {"Sodium::CryptorPK::encrypt() wrong privkey size"};

  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
  data_t ciphertext_with_mac(CryptorPK::MACSIZE + plaintext.size());

  // let's encrypt now! (combined mode, no precalculation of shared key)
  if (crypto_box_easy(ciphertext_with_mac.data(),
		      plaintext.data(), plaintext.size(),
		      nonce.data(),
		      pubkey.data(), privkey.data()) == -1)
    throw std::runtime_error {"Sodium::CryptorPK::encrypt() crypto_box_easy() failed (-1)"};

  // return with move semantics
  return ciphertext_with_mac;
}

data_t
CryptorPK::encrypt (const data_t       &plaintext,
		    const KeyPair      &keypair,
		    const Nonce<NSZPK> &nonce)
{
  // no sanity checks remaining before we get started

  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
  data_t ciphertext_with_mac(CryptorPK::MACSIZE + plaintext.size());

  // let's encrypt now! (combined mode, no precalculation of shared key)
  if (crypto_box_easy(ciphertext_with_mac.data(),
		      plaintext.data(), plaintext.size(),
		      nonce.data(),
		      keypair.pubkey().data(), keypair.privkey().data()) == -1)
    throw std::runtime_error {"Sodium::CryptorPK::encrypt(keypair...) crypto_box_easy() failed (-1)"};

  // return with move semantics
  return ciphertext_with_mac;
}

data_t
CryptorPK::decrypt (const data_t       &ciphertext_with_mac,
		    const Key          &privkey,
		    const data_t       &pubkey,
		    const Nonce<NSZPK> &nonce)
{
  // some sanity checks before we get started
  if (ciphertext_with_mac.size() < CryptorPK::MACSIZE)
    throw std::runtime_error {"CryptorPK::decrypt() ciphertext too small for MAC"};
  if (privkey.size() != KEYSIZE_PRIVKEY)
    throw std::runtime_error {"CryptorPK::decrypt() privkey wrong size"};
  if (pubkey.size()  != KEYSIZE_PUBKEY)
    throw std::runtime_error {"CryptorPK::decrypt() pubkey wrong size"};

  // make room for decrypted text
  data_t decrypted(ciphertext_with_mac.size() - CryptorPK::MACSIZE);

  // let's try to decrypt
  if (crypto_box_open_easy(decrypted.data(),
			   ciphertext_with_mac.data(),
			   ciphertext_with_mac.size(),
			   nonce.data(),
			   pubkey.data(), privkey.data()) == -1)
    throw std::runtime_error {"CryptorPK::decrypt() decryption or verification failed"};
  
  return decrypted;    			       
}

data_t
CryptorPK::decrypt (const data_t       &ciphertext_with_mac,
		    const KeyPair      &keypair,
		    const Nonce<NSZPK> &nonce)
{
  // some sanity checks before we get started
  if (ciphertext_with_mac.size() < CryptorPK::MACSIZE)
    throw std::runtime_error {"CryptorPK::decrypt() ciphertext too small for MAC"};

  // make room for decrypted text
  data_t decrypted(ciphertext_with_mac.size() - CryptorPK::MACSIZE);

  // let's try to decrypt
  if (crypto_box_open_easy(decrypted.data(),
			   ciphertext_with_mac.data(),
			   ciphertext_with_mac.size(),
			   nonce.data(),
			   keypair.pubkey().data(),
			   keypair.privkey().data()) == -1)
    throw std::runtime_error {"CryptorPK::decrypt(keypair...) decryption or verification failed"};
  
  return decrypted;    			       
}
