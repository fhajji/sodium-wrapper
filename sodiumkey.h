// sodiumkey.h -- Sodium Key Wrapper
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMKEY_H_
#define _SODIUMKEY_H_

#include <cstddef>
#include <vector>
#include <algorithm>
#include "sodiumalloc.h"

namespace Sodium {

class Key
{
 public:

  // Some common constants for typical key sizes from <sodium.h>
  static constexpr std::size_t KEYSIZE_SECRETBOX = crypto_secretbox_KEYBYTES;
  static constexpr std::size_t KEYSIZE_AUTH      = crypto_auth_KEYBYTES;

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

  Key(const unsigned char *newkey, std::size_t key_size) : keydata(key_size) {
    setkey (newkey, key_size);
    readonly();
  }
  
  Key(const Key &other)             = delete;
  Key& operator= (const Key &other) = delete;

  const unsigned char *data() const { return keydata.data(); }
  const std::size_t    size() const { return keydata.size(); }

  void setkey (const unsigned char *newkey, std::size_t newsize) {
    if (newsize != size())
      throw std::runtime_error {"Sodium::Key::setkey() newsize != oldsize"};

    // CAREFUL: will crash if key is noaccess() or readonly()
    std::copy (newkey, newkey + size(), keydata.data());
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
