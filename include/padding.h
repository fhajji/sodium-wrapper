// padding.h -- padding with the ISO/IEC 7816-4 algorithm
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
#include <algorithm>

namespace sodium {

template <typename BT=bytes>
BT pad(const BT &unpadded, const size_t blocksize)
{
	// the new size of the padded data.
	// see source code of sodium_pad() in
	// src/libsodium/sodium/utils.c:sodium_pad() for these calculations.
#if 0
	// XXX these calculations are BROKEN
	std::size_t xpadlen = blocksize - 1U;
	if ((blocksize & (blocksize - 1U)) == 0U) {
		xpadlen -= unpadded.size() & (blocksize - 1U);
	}
	else {
		xpadlen -= unpadded.size() % blocksize;
	}
#else
	// XXX we conservatively add ONE more block
	// and hope for the best.
	std::size_t xpadlen = blocksize;
#endif

	// now that we know how much the padding will take,
	// calculating the new size is easy-peasy:
	std::size_t newsize = unpadded.size() + xpadlen;

	// copy unpadded to our new extended buffer
	// XXX DANGER WILL ROBINSON: potential timing side channel attack?
	BT out(newsize);
	std::copy(unpadded.cbegin(), unpadded.cend(),
		out.begin());

	std::size_t padded_buflen_p;

	int rc = sodium_pad(&padded_buflen_p,
		reinterpret_cast<unsigned char *>(out.data()), unpadded.size(),
		blocksize, newsize);
	if (rc != 0)
		throw std::runtime_error("sodium::pad() failed");

	if (padded_buflen_p != newsize)
		out.resize(padded_buflen_p);

	return out;
}

template <typename BT=bytes>
void pad_inplace(BT &unpadded, const size_t blocksize)
{
	std::size_t unpadded_size = unpadded.size();

	// the new size of the padded data.
	// see source code of sodium_pad() in
	// src/libsodium/sodium/utils.c:sodium_pad() for these calculations.
#if 0
	// XXX these calculations are BROKEN
	std::size_t xpadlen = blocksize - 1U;
	if ((blocksize & (blocksize - 1U)) == 0U) {
		xpadlen -= unpadded_size & (blocksize - 1U);
	}
	else {
		xpadlen -= unpadded_size % blocksize;
	}
#else
	// XXX we conservatively add ONE more block (for now)
	// und hope for the best.
	std::size_t xpadlen = blocksize;
#endif
	
	// now that we know how much the padding will take,
	// calculating the new size is easy-peasy:
	std::size_t newsize = unpadded_size + xpadlen;

	unpadded.resize(newsize);
	std::size_t padded_buflen_p;

	int rc = sodium_pad(&padded_buflen_p,
		reinterpret_cast<unsigned char *>(unpadded.data()), unpadded_size,
		blocksize, newsize);
	if (rc != 0)
		throw std::runtime_error("sodium::pad_inplace() failed");

	if (padded_buflen_p != newsize)
		unpadded.resize(padded_buflen_p);
}

}