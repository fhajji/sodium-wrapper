// sodiumcrypter.cpp -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcrypter.h"
#include "sodiumnonce.h"
#include "sodiumkey.h"

#include <stdexcept>
#include <string>
#include <vector>

/**
 * Encrypt plaintext using key and nonce, returning ciphertext.
 *
 * Prior to encryption, a MAC of the plaintext is computed with key/nonce
 * and combined with the ciphertext.  This helps detect tampering of
 * the ciphertext and will also prevent decryption.
 *
 * This function will throw a std::runtime_error if the sizes of
 * the key and nonce don't make sense.
 *
 * To safely use this function, it is recommended that
 *   - NO value of nonce is EVER reused again with the same key
 * 
 * Nonces don't need to be kept secret from Eve/Oscar, and therefore
 * don't need to be stored in key_t memory. However, care MUST be
 * taken not to reuse a previously used nonce. When using a big
 * noncespace (24 bits here), generating them randomly e.g. with
 * libsodium's randombytes_buf() may be good enough... but be careful
 * nonetheless.
 *
 * The ciphertext is meant to be sent over the unsecure channel,
 * and it too won't be stored in protected key_t memory.
 **/

Sodium::Crypter::data_t
Sodium::Crypter::encrypt (const Sodium::Crypter::data_t &plaintext,
			  const Sodium::Key             &key,
			  const Sodium::Nonce<NSZ>      &nonce)
{
  // get the sizes
  const std::size_t ciphertext_size =
    crypto_secretbox_MACBYTES + plaintext.size();
  const std::size_t key_size        = Sodium::Key::KEYSIZE_SECRETBOX;
  const std::size_t nonce_size      = Sodium::NONCESIZE_SECRETBOX;
  
  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"Sodium::Crypter::encrypt() wrong key size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"Sodium::Crypter::encrypt() wrong nonce size"};
  
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

/**
 * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
 * 
 * If the ciphertext has been tampered with, decryption will fail and
 * this function with throw a std::runtime_error.
 *
 * This function will also throw a std::runtime_error if the sizes of
 * the key, nonce and ciphertext don't make sense.
 **/

Sodium::Crypter::data_t
Sodium::Crypter::decrypt (const Sodium::Crypter::data_t &ciphertext,
			  const Sodium::Key             &key,
			  const Sodium::Nonce<NSZ>      &nonce)
{
  // get the sizes
  const std::size_t key_size        = key.size();
  const std::size_t nonce_size      = nonce.size();
  const std::size_t plaintext_size  =
    ciphertext.size() - crypto_secretbox_MACBYTES;
  
  // some sanity checks before we get started
  if (key_size != Sodium::Key::KEYSIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Crypter::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_SECRETBOX)
    throw std::runtime_error {"Sodium::Crypter::decrypt() wrong nonce size"};
  if (plaintext_size <= 0)
    throw std::runtime_error {"Sodium::Crypter::decrypt() plaintext neg size"};

  // make space for decrypted buffer
  data_t decryptedtext(plaintext_size);

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptedtext.data(),
				  ciphertext.data(), ciphertext.size(),
				  nonce.data(),
				  key.data()) != 0)
    throw std::runtime_error {"Sodium::Crypter::decrypt() can't decrypt (sodium test)"};

  return decryptedtext;
}

/**
 * Convert the bytes of a ciphertext into a hex string,
 * and return that string.
 **/

std::string
Sodium::Crypter::tohex (const Sodium::Crypter::data_t &ciphertext)
{
  const std::size_t hexbuf_size = ciphertext.size() * 2 + 1;
  std::vector<char> hexbuf(hexbuf_size);
  
  // convert [ciphertext.begin(), ciphertext.end()) into hex:
  if (! sodium_bin2hex(hexbuf.data(), hexbuf_size,
		       ciphertext.data(), ciphertext.size()))
    throw std::runtime_error {"SodiumCrypter::tohex() overflowed"};

  // In C++17, we could construct a std::string with hexbuf_size chars,
  // and modify it directly through non-const data(). Unfortunately,
  // in C++11 and C++14, std::string's data() is const only, so we need
  // to copy the data over from std::vector<char> to std::string for now.
  
  // return hex output as a string:
  std::string outhex {hexbuf.begin(), hexbuf.end()};
  return outhex;
}
