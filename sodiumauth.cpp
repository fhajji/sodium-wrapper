// sodiumauth.cpp -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumauth.h"
#include "sodiumkey.h"

#include <stdexcept>
#include <vector>

/**
 * Create and return a Message Authentication Code (MAC) for the supplied
 * plaintext and secret key.
 *
 * This function will throw a std::runtime_error if the length of
 * the key doesn't make sense.
 **/

Sodium::Auth::data_t
Sodium::Auth::auth (const Sodium::Auth::data_t &plaintext,
		    const Sodium::Key          &key)
{
  // get the sizes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t key_size        = Sodium::Key::KEYSIZE_AUTH;
  std::size_t mac_size        = crypto_auth_BYTES;
  
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

/**
 * Verify MAC of plaintext using supplied secret key, returing true
 * or false whether the plaintext was tampered with or not.
 *
 * This function will throw a std::runtime_error if the sizes of
 * the key or the mac don't make sense.
 **/

bool
Sodium::Auth::verify (const Sodium::Auth::data_t &plaintext,
		      const Sodium::Auth::data_t &mac,
		      const Sodium::Key          &key)
{
  // get the sizes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t mac_size        = mac.size();
  std::size_t key_size        = key.size();
  
  // some sanity checks before we get started
  if (mac_size != crypto_auth_BYTES)
    throw std::runtime_error {"Sodium::Auth::verify() mac wrong size"};
  if (key_size != Sodium::Key::KEYSIZE_AUTH)
    throw std::runtime_error {"Sodium::Auth::verify() key wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			     plaintext.data(), plaintext_size,
			     key.data()) == 0;
}
