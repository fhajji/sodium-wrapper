// sodiumcryptoraead.cpp -- Authenticated Encryption with Added Data
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcryptoraead.h"
#include "sodiumkey.h"
#include "sodiumnonce.h"

#include <stdexcept>
#include <vector>
#include <string>


Sodium::data_t
Sodium::CryptorAEAD::encrypt (const Sodium::data_t      &header,
			      const Sodium::data_t      &plaintext,
			      const Sodium::Key         &key,
			      const Sodium::Nonce<NSZA> &nonce)
{
  // get the sizes
  const std::size_t ciphertext_size =
    plaintext.size() + Sodium::CryptorAEAD::MACSIZE;
  const std::size_t key_size        = Sodium::Key::KEYSIZE_AEAD;
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

Sodium::data_t
Sodium::CryptorAEAD::decrypt (const Sodium::data_t      &header,
			      const Sodium::data_t      &ciphertext_with_mac,
			      const Sodium::Key         &key,
			      const Sodium::Nonce<NSZA> &nonce)
{
  // get the sizes
  const std::size_t key_size   = key.size();
  const std::size_t nonce_size = nonce.size();
  const std::size_t plaintext_size =
    ciphertext_with_mac.size() - Sodium::CryptorAEAD::MACSIZE;

  // some sanity checks before we get started
  if (key_size != Sodium::Key::KEYSIZE_AEAD)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_AEAD)
    throw std::runtime_error {"Sodium::CryptorAEAD::decrypt() wrong nonce size"};
  if (ciphertext_with_mac.size() < Sodium::CryptorAEAD::MACSIZE)
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

std::string
Sodium::CryptorAEAD::tohex (const Sodium::data_t &ciphertext)
{
  const std::size_t hexbuf_size = ciphertext.size() * 2 + 1;
  std::vector<char> hexbuf(hexbuf_size);
  
  // convert [ciphertext.cbegin(), ciphertext.cend()) into hex:
  if (! sodium_bin2hex(hexbuf.data(), hexbuf_size,
                       ciphertext.data(), ciphertext.size()))
    throw std::runtime_error {"SodiumCryptor::tohex() overflowed"};

  // In C++17, we could construct a std::string with hexbuf_size chars,
  // and modify it directly through non-const data(). Unfortunately,
  // in C++11 and C++14, std::string's data() is const only, so we need
  // to copy the data over from std::vector<char> to std::string for now.
  
  // return hex output as a string:
  std::string outhex {hexbuf.cbegin(), hexbuf.cend()};
  return outhex;
}
