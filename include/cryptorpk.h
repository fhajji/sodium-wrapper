// cryptorpk.h -- Public-key encryption / decryption with MAC
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
#include "nonce.h"
#include "key.h"
#include "keypair.h"

namespace sodium {

template <typename BT=bytes>
class cryptorpk {

 public:

  static constexpr unsigned int NONCESIZE           = crypto_box_NONCEBYTES;
  static constexpr std::size_t  KEYSIZE_PUBLIC_KEY  = sodium::keypair<>::KEYSIZE_PUBLIC_KEY;
  static constexpr std::size_t  KEYSIZE_PRIVATE_KEY = sodium::keypair<>::KEYSIZE_PRIVATE_KEY;
  static constexpr std::size_t  MACSIZE             = crypto_box_MACBYTES;

  using public_key_type = sodium::keypair<>::public_key_type;
  using private_key_type = sodium::keypair<>::private_key_type;
  using nonce_type   = nonce<NONCESIZE>;
  
  /**
   * Encrypt plaintext using recipient's public key, sign it using
   * sender's private key, and a nonce. Compute an authentication tag
   * MAC as well. Return (MAC || ciphertext); i.e. ciphertext prepended
   * by MAC.
   *
   * Any modification of the returned (MAC || ciphertext) will render
   * decryption impossible.
   * 
   * The nonce is public and can be sent along the (MAC ||
   * ciphertext). The private key is private and MUST NOT be sent over
   * the channel. The public key is intended to be widely known, even
   * by attackers.
   *
   * To thwart Man-in-the-Middle attacks, it is the responsibility of
   * the recipient to verify (by other means, like certificates, web
   * of trust, etc.) that the public key of the sender does indeed
   * belong to the _real_ sender of the message. This is NOT ensured by
   * this function here.
   *
   * This function can be used repeately with the same key, but you MUST
   * then make sure never to reuse the same nonce. The easiest way to achieve
   * this is to increment nonce after or prior to each encrypt() invocation.
   * 
   * The public  key must be KEYSIZE_PUBLIC_KEY  bytes long
   * 
   * The (MAC || ciphertext) size is 
   *    MACSIZE + plaintext.size()
   * bytes long.
   **/

  BT encrypt(const BT           &plaintext,
	  const public_key_type  &public_key,
	  const private_key_type &private_key,
	  const nonce_type       &nonce)
  {
	  // some sanity checks before we get started
	  if (public_key.size() != KEYSIZE_PUBLIC_KEY)
		  throw std::runtime_error{ "sodium::cryptorpk::encrypt() wrong pubkey size" };

	  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
	  BT ciphertext_with_mac(MACSIZE + plaintext.size());

	  // let's encrypt now! (combined mode, no precalculation of shared key)
	  if (crypto_box_easy(reinterpret_cast<unsigned char *>(ciphertext_with_mac.data()),
		  reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		  nonce.data(),
		  public_key.data(), private_key.data()) == -1)
		  throw std::runtime_error{ "sodium::cryptorpk::encrypt() crypto_box_easy() failed (-1)" };

	  // return with move semantics
	  return ciphertext_with_mac;
  }

  /**
   * Encrypt plaintext using recipient's public key, sign it using
   * sender's private key, and a nonce. Compute an authentication tag
   * MAC as well. Return (MAC || ciphertext); i.e. ciphertext prepended
   * by MAC.
   *
   * The public key of the recipient and private key of the sender
   * can be provided as a keypair (e.g. for self-signed, self-addressed
   * messages).
   *
   * Otherwise, see encrypt() above.
   **/
  BT encrypt(const BT &plaintext,
	  const keypair<>    &keypair,
	  const nonce_type   &nonce)
  {
	  // no sanity checks necessary before we get started

	  // make space for MAC and encrypted message, i.e. for (MAC || encrypted)
	  BT ciphertext_with_mac(MACSIZE + plaintext.size());

	  // let's encrypt now! (combined mode, no precalculation of shared key)
	  if (crypto_box_easy(reinterpret_cast<unsigned char *>(ciphertext_with_mac.data()),
		  reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		  nonce.data(),
		  reinterpret_cast<const unsigned char *>(keypair.public_key().data()),
		  keypair.private_key().data()) == -1)
		  throw std::runtime_error{ "sodium::cryptorpk::encrypt(keypair...) crypto_box_easy() failed (-1)" };

	  // return with move semantics
	  return ciphertext_with_mac;
  }
  
  /**
   * Decrypt ciphertext using recipient's private key and nonce, and
   * verify the signature using the sender's public key, returing
   * decrypted plaintext.
   * 
   * If the ciphertext or the MAC have been tampered with, or if
   * the signature doesn't verify (e.g. because the sender isn't
   * the one who she claims to be), decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the size
   * of the public key isn't KEYSIZE_PUBLIC_KEY, or if the ciphertext
   * is even too small to hold the MAC (i.e. less than MACSIZE).
   **/

  BT decrypt(const BT           &ciphertext_with_mac,
	  const private_key_type &private_key,
	  const public_key_type  &public_key,
	  const nonce_type       &nonce)
  {
	  // some sanity checks before we get started
	  if (ciphertext_with_mac.size() < MACSIZE)
		  throw std::runtime_error{ "sodium::cryptorpk::decrypt() ciphertext too small for MAC" };
	  if (public_key.size() != KEYSIZE_PUBLIC_KEY)
		  throw std::runtime_error{ "sodium::cryptorpk::decrypt() pubkey wrong size" };

	  // make room for decrypted text
	  BT decrypted(ciphertext_with_mac.size() - MACSIZE);

	  // let's try to decrypt
	  if (crypto_box_open_easy(reinterpret_cast<unsigned char *>(decrypted.data()),
		  reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()),
		  ciphertext_with_mac.size(),
		  nonce.data(),
		  reinterpret_cast<const unsigned char *>(public_key.data()),
		  private_key.data()) == -1)
		  throw std::runtime_error{ "sodium::cryptorpk::decrypt() decryption or verification failed" };

	  return decrypted;
  }

  /**
   * Decrypt ciphertext using recipient's private key and nonce,
   * and verify the signature the signature using the sender's public
   * key, returning decrypted plaintext.
   *
   * The private key of the recipient and the public key of the sender
   * can be provided as a keypair (e.g. for self-signed, self-addressed
   * messages).
   *
   * Otherwise, see decrypt() above.
   **/
  
  BT decrypt(const BT &ciphertext_with_mac,
	  const keypair<>    &keypair,
	  const nonce_type   &nonce)
  {
	  // some sanity checks before we get started
	  if (ciphertext_with_mac.size() < MACSIZE)
		  throw std::runtime_error{ "sodium::cryptorpk::decrypt() ciphertext too small for MAC" };

	  // make room for decrypted text
	  BT decrypted(ciphertext_with_mac.size() - MACSIZE);

	  // let's try to decrypt
	  if (crypto_box_open_easy(reinterpret_cast<unsigned char *>(decrypted.data()),
		  reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()),
		  ciphertext_with_mac.size(),
		  nonce.data(),
		  reinterpret_cast<const unsigned char *>(keypair.public_key().data()),
		  keypair.private_key().data()) == -1)
		  throw std::runtime_error{ "sodium::cryptorpk::decrypt(keypair...) decryption or verification failed" };

	  return decrypted;
  }

};

} // namespace sodium
