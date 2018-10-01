// common.h -- Common data types.
//
// ISC License
//
// Copyright (C) 2018 Farid Hajji <farid@hajji.name>
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

#pragma once

#include "allocator.h"
#include <string>
#include <vector>

namespace sodium {
// libsodium treats all bytes as unsigned char
using byte = unsigned char;

// a contiguous collection of bytes in unprotected memory
using bytes = std::vector<byte>;

// a contiguous collection of bytes, interpreted as char
using chars = std::vector<char>;

// a contiguous collection of bytes, in protected memory
using bytes_protected = std::vector<byte, sodium::allocator<byte>>;

// a std::string in protected memory

// CAVEAT EMPTOR:
//   sodium::string_protected isn't always in protected memory!
//   Due to SSO, small string optimization, small strings
//   (size less than an implementation defined limit, e.g. 16 bytes)
//   are often stored in the std::basic_string object itself. If that
//   object is a local variable, the string data() will
//   be on the stack, not on the heap. Our sodium::allocator<char>
//   won't even be invoked.
//
// sodium::string_protected as currently defined is just a
// temporary solution for long, non-optimized strings.
// Don't use yet!
//
// TODO: we need a std::basic_string modification that
// explicitly avoids SSO and COW, and that places all data
// on the heap via the specified allocator. Idea: use a policy:
//    http://www.drdobbs.com/generic-a-policy-based-basicstring-imple/184403784

using string_protected =
  std::basic_string<char, std::char_traits<char>, sodium::allocator<char>>;
} // namespace sodium
