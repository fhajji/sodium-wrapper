// key.h -- Sodium Key Wrapper
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMKEY_H_
#define _SODIUMKEY_H_

#include <cstddef>
#include <vector>
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
  
  Key(std::size_t key_size) : keydata(key_size) { initialize(); readonly(); }
  
  Key(const Key &other)             = delete;
  Key& operator= (const Key &other) = delete;

  const unsigned char *data() const { return keydata.data(); }
  const std::size_t size()    const { return keydata.size(); }

  void initialize() { randombytes_buf (keydata.data(), keydata.size()); }
  void destroy()    { sodium_memzero(keydata.data(), keydata.size()); }
  
  void noaccess()  { keydata.get_allocator().noaccess(keydata.data()); }
  void readonly()  { keydata.get_allocator().readonly(keydata.data()); }
  void readwrite() { keydata.get_allocator().readwrite(keydata.data()); }

 private:
  key_t keydata;
};

} // namespace Sodium

#endif // _SODIUMKEY_H_
