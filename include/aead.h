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
#include "aead_chacha20_poly1305.h"
#include "aead_chacha20_poly1305_ietf.h"
#include "aead_xchacha20_poly1305_ietf.h"
#include "aead_aesgcm.h"
#include "aead_aesgcm_precomputed.h"
#include "aes_ctx.h"
#include <sodium.h>
#include <stdexcept>
#include <type_traits>

namespace sodium {

template <typename BT=bytes,
  typename F=sodium::aead_xchacha20_poly1305_ietf,
  typename T=typename std::enable_if<
	   std::is_same<F, sodium::aead_chacha20_poly1305>::value
	|| std::is_same<F, sodium::aead_chacha20_poly1305_ietf>::value
	|| std::is_same<F, sodium::aead_xchacha20_poly1305_ietf>::value
	|| std::is_same<F, sodium::aead_aesgcm>::value
    || std::is_same<F, sodium::aead_aesgcm_precomputed>::value
	, int
  >::type
>
class aead
{
 public:
  static constexpr std::size_t NONCESIZE = F::NPUBBYTES;
  static constexpr std::size_t KEYSIZE   = F::KEYBYTES;
  static constexpr std::size_t MACSIZE   = F::ABYTES;

  using bytes_type = BT;
  using key_type   = key<KEYSIZE>;
  using nonce_type = nonce<NONCESIZE>;

  // A aead with a new random key
  aead() : key_state_(std::move(key_type())) {}

  // A aead with a user-supplied key (copying version)
  aead(const key_type &key) : key_state_(key) {}

  // A aead with a user-supplied key (moving version)
  aead(key_type &&key) : key_state_(std::move(key)) {}

  // A copying constructor
  aead(const aead &other) :
	  key_state_(other.key_state_)
  {}

  // A moving constructor
  aead(aead &&other) :
	  key_state_(std::move(other.key_state_))
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
   * Limits: See comments in the selected F type.
   *
   * The (MAC || ciphertext) size is 
   *    MACSIZE + plaintext.size()
   * bytes.
   **/

  BT encrypt(const BT &header,
	  const BT      &plaintext,
	  const nonce_type &nonce)
  {
	  // make space for MAC and encrypted message, i.e. (MAC || encrypted)
	  BT ciphertext(MACSIZE + plaintext.size());

	  // so many bytes will really be written into output buffer
	  unsigned long long clen;

	  // let's encrypt now!
	  F::encrypt(reinterpret_cast<unsigned char *>(ciphertext.data()), &clen,
		  reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		  (header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
		  NULL /* nsec */,
		  nonce.data(),
		  key_state_.data());
	  ciphertext.resize(static_cast<std::size_t>(clen));

	  return ciphertext;
  };

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
	  if (F::decrypt(reinterpret_cast<unsigned char *>(plaintext.data()), &mlen,
		  nullptr /* nsec */,
		  reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()), ciphertext_with_mac.size(),
		  (header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
		  nonce.data(),
		  key_state_.data()) == -1)
		  throw std::runtime_error{ "sodium::aead::decrypt() can't decrypt or message/tag corrupt" };
	  plaintext.resize(static_cast<std::size_t>(mlen));

	  return plaintext;
  }

  // XXX TODO: encrypt_detached()
  // XXX TODO: decrypt_detached()

private:
	// In all but aead_aesgcm_precomputed, key_state_ is the AEAD key.
	// In aead_aesgcm_precomputed, key_state_ is the state precomputed
	// from the AEAD key with crypto_aead_aes256gcm_beforenm().
	typename std::conditional<std::is_same<F, sodium::aead_aesgcm_precomputed>::value,
		aes_ctx,
		key_type>::type key_state_;
};

// ----------------------------------------------------------------------------
// Partial specialization for the case F=aead_aesgcm_precomputed

template <typename BT>
class aead<BT, sodium::aead_aesgcm_precomputed, int>
{
public:
	static constexpr std::size_t NONCESIZE = sodium::aead_aesgcm_precomputed::NPUBBYTES;
	static constexpr std::size_t KEYSIZE   = sodium::aead_aesgcm_precomputed::KEYBYTES;
	static constexpr std::size_t MACSIZE   = sodium::aead_aesgcm_precomputed::ABYTES;

	using bytes_type = BT;
	using key_type = key<KEYSIZE>;
	using nonce_type = nonce<NONCESIZE>;

	// A aead with a new random key
	aead() {
		sodium::aead_aesgcm_precomputed::init_ctx(key_state_.data(),
			key_type().data());
	}

	// A aead with a user-supplied key (copying version)
	aead(const key_type &key) {
		sodium::aead_aesgcm_precomputed::init_ctx(key_state_.data(),
			key.data());
	}

	// A aead with a user-supplied key (moving version)
	aead(key_type &&key) {
		sodium::aead_aesgcm_precomputed::init_ctx(key_state_.data(),
			key.data());
		// XXX what do we do with key now? let it go out of scope?
	}

	// A copying constructor
	aead(const aead &other) :
		key_state_(other.key_state_) {}

	// A moving constructor
	aead(aead &&other) :
		key_state_(std::move(other.key_state_)) {}

	BT encrypt(const BT &header,
		const BT      &plaintext,
		const nonce_type &nonce)
	{
		// make space for MAC and encrypted message, i.e. (MAC || encrypted)
		BT ciphertext(MACSIZE + plaintext.size());

		// so many bytes will really be written into output buffer
		unsigned long long clen;

		// let's encrypt now!
		sodium::aead_aesgcm_precomputed::encrypt(reinterpret_cast<unsigned char *>(ciphertext.data()), &clen,
			reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
			(header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
			NULL /* nsec */,
			nonce.data(),
			key_state_.data());
		ciphertext.resize(static_cast<std::size_t>(clen));

		return ciphertext;
	}

	BT decrypt(const BT &header,
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
		if (sodium::aead_aesgcm_precomputed::decrypt(reinterpret_cast<unsigned char *>(plaintext.data()), &mlen,
			nullptr /* nsec */,
			reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()), ciphertext_with_mac.size(),
			(header.empty() ? nullptr : reinterpret_cast<const unsigned char *>(header.data())), header.size(),
			nonce.data(),
			key_state_.data()) == -1)
			throw std::runtime_error{ "sodium::aead::decrypt() can't decrypt or message/tag corrupt" };
		plaintext.resize(static_cast<std::size_t>(mlen));

		return plaintext;
	}

private:
	aes_ctx key_state_;
};

} // namespace sodium
