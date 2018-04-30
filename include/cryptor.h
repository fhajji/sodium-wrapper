// cryptor.h -- Symmetric encryption / decryption with MAC
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

#pragma once

#include "common.h"
#include "key.h"
#include "nonce.h"

#include <sodium.h>

namespace sodium {

class Cryptor {

 public:
  static constexpr std::size_t NONCESIZE = sodium::NONCESIZE_SECRETBOX;
  static constexpr std::size_t KEYSIZE   = sodium::KEYSIZE_SECRETBOX;
  static constexpr std::size_t MACSIZE   = crypto_secretbox_MACBYTES;

  using nonce_type = Nonce<NONCESIZE>;
  using key_type   = Key<KEYSIZE>;
  
  /**
   * Encrypt plaintext using key and nonce, returning ciphertext.
   *
   * During encryption, a MAC of the plaintext is computed with
   * key/nonce and combined with the ciphertext (combined mode). This
   * helps detect tampering of the ciphertext and will also prevent
   * decryption.
   *
   * To safely use this function, it is recommended that
   *   - NO value of nonce is EVER reused again with the same key
   * 
   * Nonces don't need to be kept secret from Eve/Oscar, and therefore
   * don't need to be stored in key_t memory. However, care MUST be
   * taken not to reuse a previously used nonce. When using a big
   * noncespace (24 bytes here), generating them randomly e.g. with
   * libsodium's randombytes_buf() may be good enough... but be careful
   * nonetheless.
   *
   * The ciphertext is meant to be sent over the insecure channel,
   * and it too won't be stored in protected key_t memory.
   **/

  bytes encrypt(const bytes &plaintext,
		 const key_type   &key,
		 const nonce_type &nonce);

  /**
   * Encrypt plaintext using key and nonce, returning ciphertext.
   *
   * During encryption, a MAC of the plaintext is computed with
   * key/nonce and saved in mac, which must be MACSIZE bytes long
   * (detached mode). This helps detect tampering of the ciphertext
   * and will also prevent decryption.
   *
   * This function will throw a std::runtime_error if the size of
   * the mac isn't MACSIZE.
   *
   * To safely use this function, it is recommended that
   *   - NO value of nonce is EVER reused again with the same key
   * 
   * Nonces don't need to be kept secret from Eve/Oscar, and therefore
   * don't need to be stored in key_t memory. However, care MUST be
   * taken not to reuse a previously used nonce. When using a big
   * noncespace (24 bytes here), generating them randomly e.g. with
   * libsodium's randombytes_buf() may be good enough... but be careful
   * nonetheless.
   *
   * The ciphertext and mac are meant to be sent over the insecure
   * channel, and they too won't be stored in protected key_t memory.
   **/
  
  bytes encrypt(const bytes &plaintext,
		 const key_type   &key,
		 const nonce_type &nonce,
		 bytes            &mac);
  
  /**
   * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
   * 
   * The ciphertext is assumed to contain the MAC (combined mode).
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the size of
   * the ciphertext is too small to even contain the MAC (MACSIZE bytes).
   **/

  bytes decrypt(const bytes &ciphertext,
		 const key_type   &key,
		 const nonce_type &nonce);

  /**
   * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
   * 
   * The ciphertext is assumed NOT to contain the MAC, which is to be
   * provided separatly in 'mac', a variable with MACSIZE bytes
   * (detached mode).
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the size of
   * the mac isn't MACSIZE.
   **/
  
  bytes decrypt(const bytes &ciphertext,
		 const bytes      &mac,
		 const key_type   &key,
		 const nonce_type &nonce);
};

} // namespace sodium