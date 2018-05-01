// authenticator.h -- Secret Key Authentication (MAC)
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
#include <stdexcept>
#include <sodium.h>

namespace sodium {

template <class BT=bytes>
class authenticator
{
 public:

  // Some common constants for typical key and MAC sizes from <sodium.h>
  static constexpr std::size_t KEYSIZE_AUTH = sodium::KEYSIZE_AUTH;
  static constexpr std::size_t MACSIZE      = crypto_auth_BYTES;

  // Member type aliases
  using bytes_type = BT;
  using key_type = Key<KEYSIZE_AUTH>;
  
  // An authenticator with a new random key
  authenticator() : auth_key_(std::move(key_type())) {}

  // An authenticator with a user-supplied key (copying version)
  authenticator(const key_type &auth_key) : auth_key_(auth_key) {}

  // An authenticator with a user-supplied key (moving version)
  authenticator(key_type &&auth_key) : auth_key_(std::move(auth_key)) {}

  // A copying constructor
  authenticator(const authenticator &other) :
	  auth_key_(other.auth_key_)
  {}

  // A moving constructor
  authenticator(authenticator &&other) :
	  auth_key_(std::move(other.auth_key_))
  {}

  // XXX copying and moving assignment operators?

  /**
   * Create and return a Message Authentication Code (MAC) for the supplied
   * plaintext, using the current authentication key.
   *
   * The returned MAC is MACSIZE bytes long.
   **/

  BT mac(const BT &plaintext);

  /**
   * Verify MAC of plaintext using the current authentication key,
   * returing true or false whether the plaintext has been tampered
   * with or not.
   *
   * The MAC must be MACSIZE bytes long.
   *
   * This function will throw a std::runtime_error if the size of
   * of the mac don't make sense.
   **/

  bool verify(const BT &plaintext, const BT &mac);

private:
	key_type auth_key_;
};

template<class BT>
BT
authenticator<BT>::mac(const BT &plaintext)
{
	// make space for MAC
	BT mac(authenticator<BT>::MACSIZE);

	// let's compute the MAC now!
	crypto_auth(reinterpret_cast<unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		auth_key_.data());

	// return the MAC bytes
	return mac;
}

template<class BT>
bool
authenticator<BT>::verify(const BT &plaintext, const BT &mac)
{
	// some sanity checks before we get started
	if (mac.size() != authenticator<BT>::MACSIZE)
		throw std::runtime_error{ "sodium::authenticator::verify() mac wrong size" };

	// and now verify!
	return crypto_auth_verify(reinterpret_cast<const unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		auth_key_.data()) == 0;
}

} // namespace sodium
