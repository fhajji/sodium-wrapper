// cryptor.h -- Symmetric encryption / decryption with MAC
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

#ifndef _S_CRYPTOR_H_
#define _S_CRYPTOR_H_

#include "common.h"
#include "key.h"
#include "nonce.h"

#include <sodium.h>

namespace Sodium {

class Cryptor {

 public:
  static constexpr unsigned int NSZ     = Sodium::NONCESIZE_SECRETBOX;
  static constexpr std::size_t  KEYSIZE = Key::KEYSIZE_SECRETBOX;
  static constexpr std::size_t  MACSIZE = crypto_secretbox_MACBYTES;
  
  /**
   * Encrypt plaintext using key and nonce, returning ciphertext.
   *
   * During encryption, a MAC of the plaintext is computed with
   * key/nonce and combined with the ciphertext (combined mode). This
   * helps detect tampering of the ciphertext and will also prevent
   * decryption.
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

  data_t encrypt(const data_t     &plaintext,
		 const Key        &key,
		 const Nonce<NSZ> &nonce);

  /**
   * Encrypt plaintext using key and nonce, returning ciphertext.
   *
   * During encryption, a MAC of the plaintext is computed with
   * key/nonce and saved in mac, which must be MACSIZE bytes long
   * (detached mode). This helps detect tampering of the ciphertext
   * and will also prevent decryption.
   *
   * This function will throw a std::runtime_error if the sizes of
   * the key, nonce, and mac don't make sense.
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
   * The ciphertext and mac are meant to be sent over the unsecure
   * channel, and they too won't be stored in protected key_t memory.
   **/
  
  data_t encrypt(const data_t     &plaintext,
		 const Key        &key,
		 const Nonce<NSZ> &nonce,
		 data_t           &mac);
  
  /**
   * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
   * 
   * The ciphertext is assumed to contain the MAC (combined mode).
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the sizes of
   * the key, nonce and ciphertext don't make sense.
   **/

  data_t decrypt(const data_t     &ciphertext,
		 const Key        &key,
		 const Nonce<NSZ> &nonce);

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
   * This function will also throw a std::runtime_error if the sizes of
   * the key, nonce and mac don't make sense.
   **/
  
  data_t decrypt(const data_t     &ciphertext,
		 const data_t     &mac,
		 const Key        &key,
		 const Nonce<NSZ> &nonce);

};

} // namespace Sodium
 
#endif // _S_CRYPTOR_H_
