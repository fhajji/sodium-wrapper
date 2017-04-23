// common.h -- Common data types, and function declarations.
//
// ISC License
// 
// Copyright (c) 2017 Farid Hajji <farid@hajji.name>
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

#ifndef _S_COMMON_H_
#define _S_COMMON_H_

#include <vector>
#include <string>

#include "alloc.h"

namespace Sodium {

  // data_t is a binary blob of bytes (plaintext, ciphertext, nonces, etc...)
  using data_t = std::vector<unsigned char>;

  // data2_t is a binary blob of bytes, interpreted as char instead of bytes
  using data2_t = std::vector<char>;
  
  std::string tohex (const data_t &in); // in: utils.cpp

} // namespace Sodium


#endif // _S_COMMON_H_
