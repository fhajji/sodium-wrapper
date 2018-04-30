// auth.cpp -- Secret Key Authentication (MAC)
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

#include "auth.h"
#include "key.h"

#include <stdexcept>

using bytes = sodium::bytes;
using sodium::Auth;
using sodium::Key;

bytes
Auth::auth (const bytes &plaintext,
	    const key_type &key)
{
  // make space for MAC
  bytes mac(Auth::MACSIZE);
  
  // let's compute the MAC now!
  crypto_auth (mac.data(),
	       plaintext.data(), plaintext.size(),
	       key.data());

  // return the MAC bytes
  return mac;
}

bool
Auth::verify (const bytes &plaintext,
	      const bytes &mac,
	      const key_type &key)
{
  // some sanity checks before we get started
  if (mac.size() != Auth::MACSIZE)
    throw std::runtime_error {"sodium::Auth::verify() mac wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			     plaintext.data(), plaintext.size(),
			     key.data()) == 0;
}