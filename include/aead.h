// aead.h -- Authenticated Encryption with Added Data
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
#include <stdexcept>

namespace sodium {

template <class BT=bytes>
class aead
{
 public:
  static constexpr unsigned int NSZA    = sodium::NONCESIZE_AEAD;
  static constexpr std::size_t  KEYSIZE = sodium::KEYSIZE_AEAD;
  static constexpr std::size_t  MACSIZE = crypto_aead_chacha20poly1305_ABYTES;

  using bytes_type = BT;
  using key_type   = key<KEYSIZE>;
  using nonce_type = nonce<NSZA>;

  // A aead with a new random key
  aead() : key_(std::move(key_type())) {}

  // A aead with a user-supplied key (copying version)
  aead(const key_type &key) : key_(key) {}

  // A aead with a user-supplied key (moving version)
  aead(key_type &&key) : key_(std::move(key)) {}

  // A copying constructor
  aead(const aead &other) :
	  key_(other.key_)
  {}

  // A moving constructor
  aead(aead &&other) :
	  key_(std::move(other.key_))
  {}

  // XXX copying and moving assignment operators?

  /**
   * Encrypt plaintext using aead's key and supplied nonce.
   * Compute a MAC from the ciphertext and the attached plain header.
   * Return a combination (MAC || ciphertext).
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

  BT encrypt(const BT &header,
		 const BT      &plaintext,
		 const nonce_type &nonce);

  /**
   * Decrypt ciphertext_with_mac returned by encrypt() along with
   * plain header, using aead's secret key,
   * and supplied public nonce.
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

  BT decrypt(const BT &header,
		 const BT         &ciphertext_with_mac,
		 const nonce_type &nonce);

private:
	key_type key_;
};

template <class BT>
BT
aead<BT>::encrypt(const BT &header,
	const BT         &plaintext,
	const nonce_type &nonce)
{
	// make space for MAC and encrypted message, i.e. (MAC || encrypted)
	BT ciphertext(MACSIZE + plaintext.size());

	// so many bytes will really be written into output buffer
	unsigned long long clen;

	// let's encrypt now!
	crypto_aead_chacha20poly1305_encrypt(reinterpret_cast<unsigned char *>(ciphertext.data()), &clen,
		reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		(header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
		NULL /* nsec */,
		nonce.data(),
		key_.data());
	ciphertext.resize(static_cast<std::size_t>(clen));

	return ciphertext;
}

template <class BT>
BT
aead<BT>::decrypt(const BT &header,
	const BT         &ciphertext_with_mac,
	const nonce_type &nonce)
{
	// some sanity checks before we get started
	if (ciphertext_with_mac.size() < MACSIZE)
		throw std::runtime_error{ "sodium::aead::decrypt() ciphertext length too small for a tag" };

	// make space for decrypted buffer
	BT plaintext(ciphertext_with_mac.size() - MACSIZE);

	// how many bytes we decrypt
	unsigned long long mlen;

	// and now decrypt!
	if (crypto_aead_chacha20poly1305_decrypt(reinterpret_cast<unsigned char *>(plaintext.data()), &mlen,
		nullptr /* nsec */,
		reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()), ciphertext_with_mac.size(),
		(header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
		nonce.data(),
		key_.data()) == -1)
		throw std::runtime_error{ "sodium::aead::decrypt() can't decrypt or message/tag corrupt" };
	plaintext.resize(static_cast<std::size_t>(mlen));

	return plaintext;
}

} // namespace sodium
