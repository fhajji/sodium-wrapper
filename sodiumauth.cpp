// sodiumauth.cpp -- Secret Key Authentication (MAC)
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumauth.h"

#include <stdexcept>
#include <vector>

/**
 * Create and return a Message Authentication Code (MAC) for the supplied
 * plaintext and secret key.
 *
 * This function will throw a std::runtime_error if the length of
 * the key doesn't make sense.
 *
 * To safely use this function, it is recommended that
 *   - key_t be protected memory (as declared in SodiumAuth header)
 **/

SodiumAuth::data_t
SodiumAuth::auth (const data_t &plaintext,
		  const key_t  &key)
{
  // get the sizes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t key_size        = crypto_auth_KEYBYTES;
  std::size_t mac_size        = crypto_auth_BYTES;
  
  // some sanity checks before we get started
  if (key.size() != key_size)
    throw std::runtime_error {"SodiumAuth::auth() key has wrong size"};

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
 *
 * To safely use this fnction, it is recommended that
 *  - key_t be protected memory (as declared in SodiumAuth header)
 **/

bool
SodiumAuth::verify (const data_t &plaintext,
		    const data_t &mac,
		    const key_t  &key)
{
  // get the sizes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t mac_size        = mac.size();
  std::size_t key_size        = key.size();
  
  // some sanity checks before we get started
  if (mac_size != crypto_auth_BYTES)
    throw std::runtime_error {"SodiumAuth::verify() mac has wrong size"};
  if (key_size != crypto_auth_KEYBYTES)
    throw std::runtime_error {"SodiumAuth::verify() key has wrong size"};

  // and now verify!
  return crypto_auth_verify (mac.data(),
			      plaintext.data(), plaintext_size,
			     key.data()) == 0;
}
