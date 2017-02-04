// sodiumkey.h -- Sodium Key Wrapper
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMKEY_H_
#define _SODIUMKEY_H_

#include <cstddef>
#include <vector>
#include <algorithm>
#include <string>
#include "sodiumalloc.h"

namespace Sodium {

class Key
{
 public:

  // Some common constants for typical key sizes from <sodium.h>
  static constexpr std::size_t KEYSIZE_SECRETBOX = crypto_secretbox_KEYBYTES;
  static constexpr std::size_t KEYSIZE_AUTH      = crypto_auth_KEYBYTES;
  static constexpr std::size_t KEYSIZE_SALT      = crypto_pwhash_SALTBYTES;

  // The strengh of the key derivation efforts for setpassword()
  using strength_t = enum class Strength { low, medium, high };

  // data_t is unprotected memory
  using data_t = std::vector<unsigned char>;
  
  // key_t is protected memory for bytes of key material
  //   * key_t memory will self-destruct/zero when out-of-scope / throws
  //   * key_t memory can be made readonly or temporarily non-accessible
  //   * key_t memory is stored in virtual pages protected by canary,
  //     guard pages, and access to those pages is granted with mprotect().
  using key_t = std::vector<unsigned char, SodiumAlloc<unsigned char>>;
  
  Key(std::size_t key_size, bool init=true) : keydata(key_size) {
    if (init) {
      initialize();
      readonly();
    }
    // CAREFUL: read/write uninitialized key
  }

  Key(const Key &other)             = delete;
  Key& operator= (const Key &other) = delete;

  const unsigned char *data() const { return keydata.data(); }
  const std::size_t    size() const { return keydata.size(); }

  /**
   * If the key is readwrite(), derive key material from the string
   * password, and the salt (which must be KEYSIZE_SALT bytes long)
   * and store that key material into this key object.
   *
   * The strength parameter determines how much effort is to be
   * put into the derivation of the key. It can be one of
   *    Sodium::Key::strength_t::{low,medium,high}.
   **/
  void setpass (const std::string &password,
		const data_t &salt,
		const strength_t strength = strength_t::high) {

    // check strength and set appropriate parameters
    unsigned long long strength_mem;
    unsigned long long strength_cpu;
    switch (strength) {
    case strength_t::low:
      strength_mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
      strength_cpu = crypto_pwhash_OPSLIMIT_INTERACTIVE;
      break;
    case strength_t::medium:
      strength_mem = crypto_pwhash_MEMLIMIT_MODERATE;
      strength_cpu = crypto_pwhash_OPSLIMIT_MODERATE;
      break;
    case strength_t::high:
      strength_mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
      strength_cpu = crypto_pwhash_OPSLIMIT_SENSITIVE;
    default:
      throw std::runtime_error {"Sodium:::Key::setpassword() wrong strength"};
    }

    // check salt length
    if (salt.size() != KEYSIZE_SALT)
      throw std::runtime_error {"Sodium::Key::setpassword() wrong salt size"};

    // derive a key from the hash of the password, and store it!
    if (crypto_pwhash (keydata.data(), keydata.size(),
		       password.data(), password.size(),
		       salt.data(),
		       strength_cpu,
		       strength_mem,
		       crypto_pwhash_ALG_DEFAULT) != 0)
      throw std::runtime_error {"Sodium::Key::setpassword() crypto_pwhash()"};
  }
  
  void initialize() { randombytes_buf(keydata.data(), keydata.size()); }
  void destroy()    { sodium_memzero(keydata.data(), keydata.size()); }
  
  void noaccess()  { keydata.get_allocator().noaccess(keydata.data()); }
  void readonly()  { keydata.get_allocator().readonly(keydata.data()); }
  void readwrite() { keydata.get_allocator().readwrite(keydata.data()); }

 private:
  key_t keydata;
};

} // namespace Sodium

#endif // _SODIUMKEY_H_
