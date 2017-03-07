// auth.cpp -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "auth.h"
#include "key.h"

#include <stdexcept>
#include <vector>

using Sodium::data_t;
using Sodium::Auth;
using Sodium::Key;

data_t
Auth::auth (const data_t &plaintext,
	    const Key    &key)
{
  // get the sizes
  const std::size_t key_size = Key::KEYSIZE_AUTH;
  const std::size_t mac_size = crypto_auth_BYTES;
  
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
  if (mac_size != crypto_auth_BYTES)
    throw std::runtime_error {"Sodium::Auth::verify() mac wrong size"};
  if (key_size != Key::KEYSIZE_AUTH)
    throw std::runtime_error {"Sodium::Auth::verify() key wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			     plaintext.data(), plaintext.size(),
			     key.data()) == 0;
}
