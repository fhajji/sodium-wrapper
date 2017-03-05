// sodiumcommon.h -- Common data types, and function declarations.
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCOMMON_H_
#define _SODIUMCOMMON_H_

#include <vector>
#include <string>

#include "sodiumalloc.h"

namespace Sodium {

  // data_t is a binary blob of bytes (plaintext, ciphertext, nonces, etc...)
  using data_t = std::vector<unsigned char>;

  std::string tohex (const data_t &in); // in: sodiumutils.cpp

} // namespace Sodium


#endif // _SODIUMCOMMON_H_
