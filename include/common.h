// common.h -- Common data types, and function declarations.
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _S_COMMON_H_
#define _S_COMMON_H_

#include <vector>
#include <string>

#include "alloc.h"

namespace Sodium {

  // data_t is a binary blob of bytes (plaintext, ciphertext, nonces, etc...)
  using data_t = std::vector<unsigned char>;

  std::string tohex (const data_t &in); // in: utils.cpp

} // namespace Sodium


#endif // _S_COMMON_H_
