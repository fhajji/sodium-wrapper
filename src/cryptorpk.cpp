// cryptorpk.cpp -- Public-key encryption / decryption with MAC
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
  if (nonce.size() != CryptorPK::NSZPK)
    throw std::runtime_error {"Sodium::CryptorPK::encrypt() wrong nonce size"};

  // make space for MAC and encrypted message
  data_t ciphertext_with_mac(plaintext.size() + CryptorPK::MACSIZE);

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
  // some sanity checks before we get started
  if (nonce.size() != CryptorPK::NSZPK)
    throw std::runtime_error {"CryptorPK::encrypt(keypair...) wrong nonce size"};

  // make space for MAC and encrypted message
  data_t ciphertext_with_mac(plaintext.size() + CryptorPK::MACSIZE);

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
  if (nonce.size()   != NSZPK)
    throw std::runtime_error {"CryptorPK::decrypt() wrong nonce size"};

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
  if (nonce.size()   != NSZPK)
    throw std::runtime_error {"CryptorPK::decrypt() wrong nonce size"};

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
