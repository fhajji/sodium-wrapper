// random.h -- wrappers to libsodium's CSRNG
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

#include "common.h"
#include <sodium.h>
#include <array>

namespace sodium {

using default_seed_type = std::array<unsigned char, randombytes_SEEDBYTES>;

template <typename BT=bytes>
BT randombytes_buf(const std::size_t size)
{
	BT buf(size);
	::randombytes_buf(buf.data(), buf.size());
	return buf;
}

template <typename BT=bytes>
void randombytes_buf_inplace(BT &buf)
{
	::randombytes_buf(buf.data(), buf.size());
}

template <typename BT=bytes, typename SEED_TYPE=default_seed_type>
BT randombytes_buf_deterministic(const std::size_t size, const SEED_TYPE &seed)
{
	// XXX how to determine size of seed or of SEED_TYPE
	// at compile time? This doesn't compile:
	// static_assert(seed.size() == randombytes_SEEDBYTES,
	// 	"wrong seed size");

	BT buf(size);
	::randombytes_buf_deterministic(buf.data(), buf.size(),
		reinterpret_cast<const unsigned char *>(seed.data()));
	return buf;
}

template <typename BT=bytes, typename SEED_TYPE=default_seed_type>
void randombytes_buf_deterministic_inplace(BT &buf, const SEED_TYPE &seed)
{
	// XXX how to determine size of seed or of SEED_TYPE
	// at compile time? This doesn't compile:
	// static_assert(seed.size() == randombytes_SEEDBYTES,
	// 	"wrong seed size");

	::randombytes_buf_deterministic(buf.data(), buf.size(),
		reinterpret_cast<const unsigned char *>(seed.data()));
}

template <typename SEED_TYPE=default_seed_type>
SEED_TYPE randombytes_keygen()
{
	// XXX has libsodium's randombytes_keygen() been deprecated?
	SEED_TYPE seed;
	::randombytes_buf(seed.data(), seed.size());
	return seed;
}

template <typename SEED_TYPE=default_seed_type>
void randombytes_keygen_inplace(SEED_TYPE &seed)
{
	// XXX has libsodium's randombytes_keygen() been deprecated?
	::randombytes_buf(seed.data(), seed.size());
}

} // namespace sodium
