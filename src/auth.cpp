// auth.cpp -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "auth.h"
#include "key.h"

#include <stdexcept>

using Sodium::data_t;
using Sodium::Auth;
using Sodium::Key;

data_t
Auth::auth (const data_t &plaintext,
	    const Key    &key)
{
  // get the sizes
  const std::size_t key_size = Auth::KEYSIZE_AUTH;
  const std::size_t mac_size = Auth::MACSIZE;
  
  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"Sodium::Auth::auth() key wrong size"};

  // make space for MAC
  data_t mac(mac_size);
  
  // let's compute the MAC now!
  crypto_auth (mac.data(),
	       plaintext.data(), plaintext.size(),
	       key.data());

  // return the MAC bytes
  return mac;
}

bool
Auth::verify (const data_t &plaintext,
	      const data_t &mac,
	      const Key    &key)
{
  // get the sizes
  const std::size_t mac_size = mac.size();
  const std::size_t key_size = key.size();
  
  // some sanity checks before we get started
  if (mac_size != Auth::MACSIZE)
    throw std::runtime_error {"Sodium::Auth::verify() mac wrong size"};
  if (key_size != Auth::KEYSIZE_AUTH)
    throw std::runtime_error {"Sodium::Auth::verify() key wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			     plaintext.data(), plaintext.size(),
			     key.data()) == 0;
}
