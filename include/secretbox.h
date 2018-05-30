// secretbox.h -- Symmetric encryption / decryption with MAC
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

template <class BT=bytes>
class secretbox {

 public:
  static constexpr std::size_t NONCESIZE = sodium::NONCESIZE_SECRETBOX;
  static constexpr std::size_t KEYSIZE   = sodium::KEYSIZE_SECRETBOX;
  static constexpr std::size_t MACSIZE   = crypto_secretbox_MACBYTES;

  using bytes_type = BT;
  using nonce_type = nonce<NONCESIZE>;
  using key_type   = key<KEYSIZE>;

  // A secretbox with a new random key
  secretbox() : key_(std::move(key_type())) {}

  // A secretbox with a user-supplied key (copying version)
  secretbox(const key_type &key) : key_(key) {}

  // A secretbox with a user-supplied key (moving version)
  secretbox(key_type &&key) : key_(std::move(key)) {}

  // A copying constructor
  secretbox(const secretbox &other) :
	  key_(other.key_)
  {}

  // A moving constructor
  secretbox(secretbox &&other) :
	  key_(std::move(other.key_))
  {}

  // XXX copying and moving assignment operators?

  /**
   * Encrypt plaintext using secretbox's key and supplied nonce,
   * returning ciphertext.
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
   * don't need to be stored in key_type memory. However, care MUST be
   * taken not to reuse a previously used nonce. When using a big
   * noncespace (24 bytes here), generating them randomly e.g. with
   * libsodium's randombytes_buf() may be good enough... but be careful
   * nonetheless.
   *
   * The ciphertext is meant to be sent over the insecure channel,
   * and it too won't be stored in protected key_type memory.
   **/

  BT encrypt(const BT &plaintext,
		 const nonce_type &nonce);

  /**
  * In-place variant.
  *
  * XXX Document me (yada, yada, yada...)
  **/

  void encrypt(BT &ciphertext_with_mac,
	  const BT &plaintext,
	  const nonce_type &nonce);

  /**
   * Encrypt plaintext using secretbox's key and supplied nonce,
   * returning ciphertext and MAC.
   *
   * During encryption, a MAC of the plaintext is computed with
   * key/nonce and saved in mac, which must be MACSIZE bytes long
   * (detached mode). This helps detect tampering of the ciphertext,
   * or of the MAC, and will also prevent decryption.
   *
   * This function will throw a std::runtime_error if the size of
   * the mac isn't MACSIZE.
   *
   * To safely use this function, it is recommended that
   *   - NO value of nonce is EVER reused again with the same key
   * 
   * Nonces don't need to be kept secret from Eve/Oscar, and therefore
   * don't need to be stored in key_type memory. However, care MUST be
   * taken not to reuse a previously used nonce. When using a big
   * noncespace (24 bytes here), generating them randomly e.g. with
   * libsodium's randombytes_buf() may be good enough... but be careful
   * nonetheless.
   *
   * The ciphertext and mac are meant to be sent over the insecure
   * channel, and they too won't be stored in protected key_type memory.
   **/
  
  BT encrypt(const BT &plaintext,
		 const nonce_type &nonce,
		 BT               &mac);

  /**
  * In-place variant.
  *
  * XXX Document me (yada, yada, yada...)
  **/

  void encrypt(BT &ciphertext,
	  const BT &plaintext,
	  const nonce_type &nonce,
	  BT               &mac);
  
  /**
   * Decrypt ciphertext using secretbox's key and supplied nonce,
   * returing decrypted plaintext.
   * 
   * The ciphertext is assumed to contain the MAC (combined mode).
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the size of
   * the ciphertext is too small to even contain the MAC (MACSIZE bytes).
   **/

  BT decrypt(const BT &ciphertext_with_mac,
		 const nonce_type &nonce);

  /**
  * In-place variant.
  *
  * XXX Document me (yada, yada, yada...)
  **/

  void decrypt(BT &decrypted,
	  const BT &ciphertext_with_mac,
	  const nonce_type &nonce);

  /**
   * Decrypt ciphertext using secretbox's key and supplied nonce,
   * returing decrypted plaintext.
   * 
   * The ciphertext is assumed NOT to contain the MAC, which is to be
   * provided separatly in 'mac', a variable with MACSIZE bytes
   * (detached mode).
   * 
   * If the ciphertext or the MAC have been tampered with, decryption
   * will fail and this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the size of
   * the mac isn't MACSIZE.
   **/
  
  BT decrypt(const BT  &ciphertext,
	  const nonce_type &nonce,
	  const BT         &mac);

  /**
  * In-place variant.
  *
  * XXX Document me (yada, yada, yada...)
  **/

  void decrypt(BT &decrypted,
	  const BT  &ciphertext,
	  const nonce_type &nonce,
	  const BT         &mac);

private:
	key_type key_;
};

template <class BT>
BT
secretbox<BT>::encrypt(const BT &plaintext,
	const nonce_type &nonce)
{
	// make space for MAC and encrypted message,
	// combined form, i.e. (MAC || encrypted)
	BT ciphertext_with_mac(MACSIZE + plaintext.size());

	// let's encrypt now!
	crypto_secretbox_easy(reinterpret_cast<unsigned char *>(ciphertext_with_mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()),
		plaintext.size(),
		nonce.data(),
		key_.data());

	// return the encrypted bytes
	return ciphertext_with_mac;
}

template <class BT>
void
secretbox<BT>::encrypt(BT &ciphertext_with_mac,
	const BT &plaintext,
	const nonce_type &nonce)
{
	// sanity check before we get started:
	if (ciphertext_with_mac.size() != plaintext.size() + MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::encrypt() wrong ciphertext_with_mac size" };

	// let's encrypt now!
	crypto_secretbox_easy(reinterpret_cast<unsigned char *>(ciphertext_with_mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()),
		plaintext.size(),
		nonce.data(),
		key_.data());

	// ciphertext_with_mac is the implicit return value
}

template <class BT>
BT
secretbox<BT>::encrypt(const BT &plaintext,
	const nonce_type &nonce,
	BT               &mac)
{
	// some sanity checks before we get started
	if (mac.size() != MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::encrypt(detached) wrong mac size" };

	// make space for encrypted message
	// detached form, stream cipher => same size as plaintext.
	BT ciphertext(plaintext.size());

	// let's encrypt now!
	crypto_secretbox_detached(reinterpret_cast<unsigned char *>(ciphertext.data()),
		reinterpret_cast<unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()),
		plaintext.size(),
		nonce.data(),
		key_.data());

	// return the encrypted bytes (mac is returned by reference)
	return ciphertext; // by move semantics
}

template <class BT>
void
secretbox<BT>::encrypt(BT &ciphertext,
	const BT &plaintext,
	const nonce_type &nonce,
	BT               &mac)
{
	// some sanity checks before we get started
	if (ciphertext.size() != plaintext.size())
		throw std::runtime_error{ "sodium::secretbox::encrypt(detached) wrong ciphertext size" };
	if (mac.size() != MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::encrypt(detached) wrong mac size" };

	// let's encrypt now!
	crypto_secretbox_detached(reinterpret_cast<unsigned char *>(ciphertext.data()),
		reinterpret_cast<unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()),
		plaintext.size(),
		nonce.data(),
		key_.data());

	// ciphertext and mac are returned by reference
}

template <class BT>
BT
secretbox<BT>::decrypt(const BT &ciphertext_with_mac,
	const nonce_type &nonce)
{
	// some sanity checks before we get started
	if (ciphertext_with_mac.size() < MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::decrypt(combined) ciphertext_with_mac too small for mac" };

	// make space for decrypted buffer
	BT decrypted(ciphertext_with_mac.size() - MACSIZE);

	// and now decrypt!
	if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char *>(decrypted.data()),
		reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()),
		ciphertext_with_mac.size(),
		nonce.data(),
		key_.data()) != 0)
		throw std::runtime_error{ "sodium::secretbox::decrypt(combined) can't decrypt" };

	return decrypted;
}

template <class BT>
void
secretbox<BT>::decrypt(BT &decrypted,
	const BT         &ciphertext_with_mac,
	const nonce_type &nonce)
{
	// some sanity checks before we get started
	if (ciphertext_with_mac.size() < MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::decrypt(combined) ciphertext_with_mac too small for mac" };
	if (decrypted.size() != ciphertext_with_mac.size() - MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::decrypt(combined) decrypted wrong size" };

	// and now decrypt!
	if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char *>(decrypted.data()),
		reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()),
		ciphertext_with_mac.size(),
		nonce.data(),
		key_.data()) != 0)
		throw std::runtime_error{ "sodium::secretbox::decrypt(combined) can't decrypt" };

	// decrypted is returned by reference
}

template <class BT>
BT
secretbox<BT>::decrypt(const BT &ciphertext,
	const nonce_type &nonce,
	const BT         &mac)
{
	// some sanity checks before we get started
	if (mac.size() != MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::decrypt(detached) wrong mac size" };

	// make space for decrypted buffer;
	// detached mode. stream cipher => decryptedtext size == ciphertext size
	BT decrypted(ciphertext.size());

	// and now decrypt!
	if (crypto_secretbox_open_detached(reinterpret_cast<unsigned char *>(decrypted.data()),
		reinterpret_cast<const unsigned char *>(ciphertext.data()),
		reinterpret_cast<const unsigned char *>(mac.data()),
		ciphertext.size(),
		nonce.data(),
		key_.data()) != 0)
		throw std::runtime_error{ "sodium::secretbox::decrypt(detached) can't decrypt" };

	return decrypted; // by move semantics
}

template <class BT>
void
secretbox<BT>::decrypt(BT &decrypted,
	const BT         &ciphertext,
	const nonce_type &nonce,
	const BT         &mac)
{
	// some sanity checks before we get started
	if (decrypted.size() != ciphertext.size())
		throw std::runtime_error{ "sodium::secretbox::decrypt(detached) wrong decrypted size" };
	if (mac.size() != MACSIZE)
		throw std::runtime_error{ "sodium::secretbox::decrypt(detached) wrong mac size" };

	// and now decrypt!
	if (crypto_secretbox_open_detached(reinterpret_cast<unsigned char *>(decrypted.data()),
		reinterpret_cast<const unsigned char *>(ciphertext.data()),
		reinterpret_cast<const unsigned char *>(mac.data()),
		ciphertext.size(),
		nonce.data(),
		key_.data()) != 0)
		throw std::runtime_error{ "sodium::secretbox::decrypt(detached) can't decrypt" };

	// decrypted is returned by reference
}

} // namespace sodium
