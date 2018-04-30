// cryptoraead.h -- Authenticated Encryption with Added Data
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

namespace sodium {

class CryptorAEAD
{
 public:
  static constexpr unsigned int NSZA    = sodium::NONCESIZE_AEAD;
  static constexpr std::size_t  KEYSIZE = sodium::KEYSIZE_AEAD;
  static constexpr std::size_t  MACSIZE = crypto_aead_chacha20poly1305_ABYTES;

  using key_type   = Key<KEYSIZE>;
  using nonce_type = Nonce<NSZA>;
  
  /**
   * Encrypt plaintext using key and nonce. Compute a MAC from the
   * ciphertext and the attached plain header. Return a combination
   * (MAC || ciphertext).
   *
   * Any modification of the returned (MAC || ciphertext), OR of the
   * header, will render decryption impossible. The intended
   * application is to send encrypted message bodies along with
   * unencrypted message headers, but to protect both the bodies and
   * headers with the MAC. The nonce is public and can be sent along
   * the (MAC || ciphertext). The key is private and MUST NOT be sent
   * over the channel.
   *
   * This function can be used repeately with the same key, but you
   * MUST then make sure never to reuse the same nonce. The easiest
   * way to achieve this is to increment nonce after or prior to each
   * encrypt() invocation.
   * 
   * Limits: Up to 2^64 messages with the same key,
   *         Up to 2^70 bytes per message.
   *
   * The (MAC || ciphertext) size is 
   *    MACSIZE + plaintext.size()
   * bytes.
   **/

  bytes encrypt(const bytes &header,
		 const bytes      &plaintext,
		 const key_type   &key,
		 const nonce_type &nonce);

  /**
   * Decrypt ciphertext_with_mac returned by encrypt() along with
   * plain header, using secret key, and public nonce.
   * 
   * If decryption succeeds, return plaintext.
   *
   * If the ciphertext, embedded MAC, or plain header have been
   * tampered with, or, in general, if the decryption doesn't succeed,
   * throw a std::runtime_error.
   * 
   * The nonce can be public, the key must remain private. To
   * successfully decrypt a message, both the key and nonce must be
   * the same value as those used when encrypting.
   **/

  bytes decrypt(const bytes &header,
		 const bytes        &ciphertext_with_mac,
		 const key_type   &key,
		 const nonce_type &nonce);
};

} // namespace sodium