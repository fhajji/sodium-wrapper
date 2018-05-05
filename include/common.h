// common.h -- Common data types, and function declarations.
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

#include <vector>
#include <string>

#include "alloc.h"

namespace sodium {
	// libsodium treats all bytes as unsigned char
	using byte = unsigned char;

	// a contiguous collection of bytes in unprotected memory
	using bytes = std::vector<byte>;

	// a contiguous collection of bytes, interpreted as char
	using chars = std::vector<char>;

	// a contiguous collection of bytes, in protected memory
	using bytes_protected = std::vector<byte, SodiumAlloc<byte>>;  // key_t

	std::string tohex (const bytes &in); // in: utils.cpp
	std::string tohex (const chars &in); // in: utils.cpp
} // namespace sodium