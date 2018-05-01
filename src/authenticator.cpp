// authenticator.cpp -- Secret Key Authentication (MAC)
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

#include "authenticator.h"
#include "key.h"

#include <stdexcept>

using bytes = sodium::bytes;
using chars = sodium::chars;
using sodium::authenticator;
using sodium::Key;

bytes
authenticator::mac (const bytes &plaintext)
{
  // make space for MAC
  bytes mac(authenticator::MACSIZE);
  
  // let's compute the MAC now!
  crypto_auth (mac.data(),
	       plaintext.data(), plaintext.size(),
	       auth_key_.data());

  // return the MAC bytes
  return mac;
}

chars
authenticator::mac(const chars &plaintext)
{
	// make space for MAC
	chars mac(authenticator::MACSIZE);

	// let's compute the MAC now!
	crypto_auth(reinterpret_cast<unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		auth_key_.data());

	// return the MAC bytes
	return mac;
}

bool
authenticator::verify (const bytes &plaintext, const bytes &mac)
{
  // some sanity checks before we get started
  if (mac.size() != authenticator::MACSIZE)
    throw std::runtime_error {"sodium::authenticator::verify() mac wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			     plaintext.data(), plaintext.size(),
			     auth_key_.data()) == 0;
}

bool
authenticator::verify(const chars &plaintext, const chars &mac)
{
	// some sanity checks before we get started
	if (mac.size() != authenticator::MACSIZE)
		throw std::runtime_error{ "sodium::authenticator::verify() mac wrong size" };

	// and now verify!
	return crypto_auth_verify(reinterpret_cast<const unsigned char *>(mac.data()),
		reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
		auth_key_.data()) == 0;
}