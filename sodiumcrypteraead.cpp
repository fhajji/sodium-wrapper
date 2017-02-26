// sodiumcrypteraead.cpp -- Authenticated Encryption with Added Data
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumcrypteraead.h"
#include "sodiumkey.h"
#include "sodiumnonce.h"

#include <stdexcept>
#include <vector>
#include <string>

/**
 * Encrypt plaintext using key and nonce. Compute a MAC from the ciphertext
 * and the attached plain header. Return a combination MAC+ciphertext.
 *
 * Any modification of the returned MAC+ciphertext, OR of the header, will
 * render decryption impossible. The intended application is to send
 * encrypted message bodies along with unencrypted message headers, but to
 * protect both the bodies and headers with the MAC. The nonce is public
 * and can be sent along the MAC+ciphertext. The key is private and MUST NOT
 * be sent over the channel.
 *
 * This function can be used repeately with the same key, but you MUST
 * then make sure never to reuse the same nonce. The easiest way to achieve
 * this is to increment nonce after or prior to each encrypt() invocation.
 * 
 * Limits: Up to 2^64 messages with the same key,
 *         Up to 2^70 bytes per message.
 *
 * The key   must be Sodium::Key::KEYSIZE_AEAD bytes long
 * The nonce must be Sodium::NONCESIZE_AEAD    bytes long
 *
 * The MAC+ciphertext size is 
 *    plaintext.size() + Sodium::CrypterAEAD::MACSIZE.
 **/

Sodium::CrypterAEAD::data_t
Sodium::CrypterAEAD::encrypt (const Sodium::CrypterAEAD::data_t &header,
			      const Sodium::CrypterAEAD::data_t &plaintext,
			      const Sodium::Key                 &key,
			      const Sodium::Nonce<NSZA>         &nonce)
{
  // get the sizes
  const std::size_t ciphertext_size =
    plaintext.size() + Sodium::CrypterAEAD::MACSIZE;
  const std::size_t key_size        = Sodium::Key::KEYSIZE_AEAD;
  const std::size_t nonce_size      = Sodium::NONCESIZE_AEAD;

  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"Sodium::CrypterAEAD::encrypt() wrong key size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"Sodium::CrypterAEAD::encrypt() wrong nonce size"};

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

/**
 * Decrypt ciphertext_with_mac returned by Sodium::CrypterAEAD::encrypt()
 * along with plain header, using secret key, and public nonce.
 * 
 * If decryption succeeds, return plaintext.
 *
 * If the ciphertext, embedded MAC, or plain header have been tampered with,
 * or, in general, if the decryption doesn't succeed, throw a
 * std::runtime_error.
 * 
 * The key   must be Sodium::Key::KEYSIZE_AEAD bytes long
 * The nonce must be Sodium::NONCESIZE_AEAD    bytes long
 * 
 * The nonce can be public, the key must remain private. To successfully
 * decrypt a message, both the key and nonce must be the same as those
 * used when encrypting.
 **/

Sodium::CrypterAEAD::data_t
Sodium::CrypterAEAD::decrypt (const Sodium::CrypterAEAD::data_t &header,
			      const Sodium::CrypterAEAD::data_t &ciphertext_with_mac,
			      const Sodium::Key                 &key,
			      const Sodium::Nonce<NSZA>         &nonce)
{
  // get the sizes
  const std::size_t key_size   = key.size();
  const std::size_t nonce_size = nonce.size();
  const std::size_t plaintext_size =
    ciphertext_with_mac.size() - Sodium::CrypterAEAD::MACSIZE;

  // some sanity checks before we get started
  if (key_size != Sodium::Key::KEYSIZE_AEAD)
    throw std::runtime_error {"Sodium::CrypterAEAD::decrypt() wrong key size"};
  if (nonce_size != Sodium::NONCESIZE_AEAD)
    throw std::runtime_error {"Sodium::CrypterAEAD::decrypt() wrong nonce size"};
  if (plaintext_size < 0)
    throw std::runtime_error {"Sodium::CrypterAEAD::decrypt() ciphertext length too small for a tag"};

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
    throw std::runtime_error {"Sodium::CrypterAEAD::decrypt() can't decrypt or message/tag corrupt"};
  plaintext.resize(mlen);

  return plaintext;
}

/**
 * Convert the bytes of a ciphertext into a hex string,
 * and return that string.
 **/

std::string
Sodium::CrypterAEAD::tohex (const Sodium::CrypterAEAD::data_t &ciphertext)
{
  const std::size_t hexbuf_size = ciphertext.size() * 2 + 1;
  std::vector<char> hexbuf(hexbuf_size);
  
  // convert [ciphertext.cbegin(), ciphertext.cend()) into hex:
  if (! sodium_bin2hex(hexbuf.data(), hexbuf_size,
                       ciphertext.data(), ciphertext.size()))
    throw std::runtime_error {"SodiumCrypter::tohex() overflowed"};

  // In C++17, we could construct a std::string with hexbuf_size chars,
  // and modify it directly through non-const data(). Unfortunately,
  // in C++11 and C++14, std::string's data() is const only, so we need
  // to copy the data over from std::vector<char> to std::string for now.
  
  // return hex output as a string:
  std::string outhex {hexbuf.cbegin(), hexbuf.cend()};
  return outhex;
}
