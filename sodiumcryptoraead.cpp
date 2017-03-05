// sodiumcryptoraead.cpp -- Authenticated Encryption with Added Data
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcryptoraead.h"
#include "sodiumkey.h"
#include "sodiumnonce.h"

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
