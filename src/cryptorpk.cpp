// cryptorpk.cpp -- Public-key encryption / decryption with MAC
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

#include "common.h"
#include "cryptorpk.h"

#include <stdexcept>
#include <sodium.h>

using bytes = sodium::bytes;
using sodium::CryptorPK;
using sodium::KeyPair;

bytes
CryptorPK::encrypt (const bytes       &plaintext,
		    const bytes       &pubkey,
		    const privkey_type &privkey,
		    const nonce_type   &nonce)
{
  // some sanity checks before we get started
  if (pubkey.size() != CryptorPK::KEYSIZE_PUBKEY)
    throw std::runtime_error {"sodium::CryptorPK::encrypt() wrong pubkey size"};

  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
  bytes ciphertext_with_mac(CryptorPK::MACSIZE + plaintext.size());

  // let's encrypt now! (combined mode, no precalculation of shared key)
  if (crypto_box_easy(ciphertext_with_mac.data(),
		      plaintext.data(), plaintext.size(),
		      nonce.data(),
		      pubkey.data(), privkey.data()) == -1)
    throw std::runtime_error {"sodium::CryptorPK::encrypt() crypto_box_easy() failed (-1)"};

  // return with move semantics
  return ciphertext_with_mac;
}

bytes
CryptorPK::encrypt (const bytes     &plaintext,
		    const KeyPair    &keypair,
		    const nonce_type &nonce)
{
  // no sanity checks necessary before we get started

  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
  bytes ciphertext_with_mac(CryptorPK::MACSIZE + plaintext.size());

  // let's encrypt now! (combined mode, no precalculation of shared key)
  if (crypto_box_easy(ciphertext_with_mac.data(),
		      plaintext.data(), plaintext.size(),
		      nonce.data(),
		      keypair.pubkey().data(), keypair.privkey().data()) == -1)
    throw std::runtime_error {"sodium::CryptorPK::encrypt(keypair...) crypto_box_easy() failed (-1)"};

  // return with move semantics
  return ciphertext_with_mac;
}

bytes
CryptorPK::decrypt (const bytes       &ciphertext_with_mac,
		    const privkey_type &privkey,
		    const bytes        &pubkey,
		    const nonce_type   &nonce)
{
  // some sanity checks before we get started
  if (ciphertext_with_mac.size() < CryptorPK::MACSIZE)
    throw std::runtime_error {"sodium::CryptorPK::decrypt() ciphertext too small for MAC"};
  if (pubkey.size()  != KEYSIZE_PUBKEY)
    throw std::runtime_error {"sodium::CryptorPK::decrypt() pubkey wrong size"};

  // make room for decrypted text
  bytes decrypted(ciphertext_with_mac.size() - CryptorPK::MACSIZE);

  // let's try to decrypt
  if (crypto_box_open_easy(decrypted.data(),
			   ciphertext_with_mac.data(),
			   ciphertext_with_mac.size(),
			   nonce.data(),
			   pubkey.data(), privkey.data()) == -1)
    throw std::runtime_error {"sodium::CryptorPK::decrypt() decryption or verification failed"};
  
  return decrypted;    			       
}

bytes
CryptorPK::decrypt (const bytes     &ciphertext_with_mac,
		    const KeyPair    &keypair,
		    const nonce_type &nonce)
{
  // some sanity checks before we get started
  if (ciphertext_with_mac.size() < CryptorPK::MACSIZE)
    throw std::runtime_error {"sodium::CryptorPK::decrypt() ciphertext too small for MAC"};

  // make room for decrypted text
  bytes decrypted(ciphertext_with_mac.size() - CryptorPK::MACSIZE);

  // let's try to decrypt
  if (crypto_box_open_easy(decrypted.data(),
			   ciphertext_with_mac.data(),
			   ciphertext_with_mac.size(),
			   nonce.data(),
			   keypair.pubkey().data(),
			   keypair.privkey().data()) == -1)
    throw std::runtime_error {"sodium::CryptorPK::decrypt(keypair...) decryption or verification failed"};
  
  return decrypted;    			       
}