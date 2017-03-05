// sodiumcryptor.cpp -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcryptor.h"
#include "sodiumnonce.h"
#include "sodiumkey.h"

#include <stdexcept>
#include <string>
#include <vector>

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
  const std::size_t plaintext_size  =
    ciphertext.size() - crypto_secretbox_MACBYTES;
  
  // some sanity checks before we get started
  if (key_size != Key::KEYSIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() wrong nonce size"};
  if (plaintext_size <= 0)
    throw std::runtime_error {"Sodium::Cryptor::decrypt() plaintext neg size"};

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

std::string
Cryptor::tohex (const data_t &ciphertext)
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
