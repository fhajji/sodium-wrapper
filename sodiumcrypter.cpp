// sodiumcrypter.cpp -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcrypter.h"

#include <stdexcept>
#include <string>
#include <vector>

/**
 * Encrypt plaintext using key and nonce, returning cyphertext.
 *
 * Prior to encryption, a MAC of the plaintext is computed with key/nonce
 * and combined with the cyphertext.  This helps detect tampering of
 * the cyphertext and will also prevent decryption.
 *
 * This function will throw a std::runtime_error if the sizes of
 * the key and nonce don't make sense.
 *
 * To safely use this function, it is recommended that
 *   - key_t be protected memory (as declared in SodiumCrypter header)
 *   - NO value of nonce is EVER reused again.
 * 
 * Nonces don't need to be kept secret from Eve/Oscar, and therefore
 * don't need to be stored in key_t memory. However, care MUST be
 * taken not to reuse a previously used nonce. When using a big
 * noncespace (24 bits here), generating them randomly e.g. with
 * libsodium's randombytes_buf() may be good enough... but be careful
 * nonetheless.
 *
 * The cyphertext is meant to be sent over the unsecure channel,
 * and it too won't be stored in protected key_t memory.
 **/

SodiumCrypter::data_t
SodiumCrypter::encrypt (const data_t &plaintext,
		        const key_t  &key,
		        const data_t &nonce)
{
  // get the sizes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() key has wrong size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() nonce has wrong size"};

  // make space for MAC and encrypted message
  data_t cyphertext(cyphertext_size);
  
  // let's encrypt now!
  crypto_secretbox_easy (cyphertext.data(),
			 plaintext.data(), plaintext.size(),
			 nonce.data(),
			 key.data());

  // return the encrypted bytes
  return cyphertext;
}

/**
 * Decrypt cyphertext using key and nonce, returing decrypted plaintext.
 * 
 * If the cyphertext has been tampered with, decryption will fail and
 * this function with throw a std::runtime_error.
 *
 * This function will also throw a std::runtime_error if the sizes of
 * the key, nonce and cyphertext don't make sense.
 *
 * To use this function safely, it is recommended that
 *   - key_t be protected memory (as declared in SodiumCrypter header)
 **/

SodiumCrypter::data_t
SodiumCrypter::decrypt (const data_t &cyphertext,
		        const key_t  &key,
		        const data_t &nonce)
{
  // get the sizes
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t key_size        = key.size();
  std::size_t nonce_size      = nonce.size();
  std::size_t plaintext_size  = cyphertext_size - crypto_secretbox_MACBYTES;
  
  // some sanity checks before we get started
  if (key_size != crypto_secretbox_KEYBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() key has wrong size"};
  if (nonce_size != crypto_secretbox_NONCEBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() nonce has wrong size"};
  if (plaintext_size <= 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() plaintext negative size"};

  // make space for decrypted buffer
  data_t decryptedtext(plaintext_size);

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptedtext.data(),
				  cyphertext.data(), cyphertext_size,
				  nonce.data(),
				  key.data()) != 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() message forged (sodium test)"};

  return decryptedtext;
}

/**
 * Convert the bytes of a cyphertext into a hex string,
 * and return that string.
 **/

std::string
SodiumCrypter::tohex (const data_t &cyphertext)
{
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t hex_size        = cyphertext_size * 2 + 1;

  std::vector<char> hexbuf(hex_size);
  
  // convert [cypherbuf, cypherbuf + cyphertext_size] into hex:
  if (! sodium_bin2hex(hexbuf.data(), hex_size,
		       cyphertext.data(), cyphertext_size))
    throw std::runtime_error {"SodiumCrypter::tohex() overflowed"};

  // XXX: is copying hexbuf into a string really necessary here?
  
  // return hex output as a string:
  std::string outhex {hexbuf.data(), hexbuf.data() + hex_size};
  return outhex;
}
