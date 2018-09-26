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
#include <algorithm>
#include <sodium.h>

namespace sodium {

/**
 * Add padding to the buffer unpadded, such that the padded
 * result has a multiple of blocksize length.
 *
 * The input buffer unpadded is left unchanged.
 *
 * Throw a std::runtime_error if an error is reported
 * by the wrapped libsodium function.
 *
 * Return a padded copy of the input buffer.
 *
 * Wrapped libsodium function:
 *     sodium_pad()
 **/

template<typename BT = bytes>
BT
pad(const BT& unpadded, const size_t blocksize)
{
    // we conservatively add ONE more block
    // and hope for the best.
    std::size_t xpadlen = blocksize;

    // now that we know how much the padding will take,
    // calculating the new size is easy-peasy:
    std::size_t newsize = unpadded.size() + xpadlen;

    // copy unpadded to our new extended buffer
    // XXX DANGER WILL ROBINSON: potential timing side channel attack?
    BT out(newsize);
    std::copy(unpadded.cbegin(), unpadded.cend(), out.begin());

    std::size_t padded_buflen_p;

    int rc = sodium_pad(&padded_buflen_p,
                        reinterpret_cast<unsigned char*>(out.data()),
                        unpadded.size(),
                        blocksize,
                        newsize);
    if (rc != 0)
        throw std::runtime_error("sodium::pad() failed");

    if (padded_buflen_p != newsize)
        out.resize(padded_buflen_p);

    return out;
}

/**
 * Add padding to the buffer unpadded, such that the padded
 * result has a multiple of blocksize length.
 *
 * The input buffer is padded in place, i.e. it will be resize()d.
 *
 * As usual with resize(), this invalidates all iterators
 * pointing into unpadded.
 *
 * Throw a std::runtime_error if an error is reported
 * by the wrapped libsodium function.
 *
 * Wrapped libsodium function:
 *     sodium_pad()
 **/

template<typename BT = bytes>
void
pad_inplace(BT& unpadded, const size_t blocksize)
{
    std::size_t unpadded_size = unpadded.size();

    // XXX we conservatively add ONE more block (for now)
    // und hope for the best.
    std::size_t xpadlen = blocksize;

    // now that we know how much the padding will take,
    // calculating the new size is easy-peasy:
    std::size_t newsize = unpadded_size + xpadlen;

    unpadded.resize(newsize);
    std::size_t padded_buflen_p;

    int rc = sodium_pad(&padded_buflen_p,
                        reinterpret_cast<unsigned char*>(unpadded.data()),
                        unpadded_size,
                        blocksize,
                        newsize);
    if (rc != 0)
        throw std::runtime_error("sodium::pad_inplace() failed");

    if (padded_buflen_p != newsize)
        unpadded.resize(padded_buflen_p);
}

/**
 * Remove padding from the buffer padded.
 *
 * The input buffer padded is left unchanged.
 *
 * Throw a std::runtime_error if an error is reported
 * by the wrapped libsodium function. This can e.g.
 * happen with a malformed pad.
 *
 * Return an unpadded copy of the padded input buffer.
 *
 * Wrapped libsodium function:
 *     sodium_unpad()
 **/

template<typename BT = bytes>
BT
unpad(const BT& padded, const size_t blocksize)
{
    std::size_t unpadded_buflen_p;

    int rc = sodium_unpad(&unpadded_buflen_p,
                          reinterpret_cast<const unsigned char*>(padded.data()),
                          padded.size(),
                          blocksize);
    if (rc != 0)
        throw std::runtime_error("sodium::unpad() failed");

    BT out(unpadded_buflen_p);
    std::copy_n(padded.cbegin(), unpadded_buflen_p, out.begin());

    return out;
}

/**
 * Remove padding from the buffer padded.
 *
 * The input padded buffer is unpadded in place,
 * i.e. it will be resize()d.
 *
 * As usual with resize(), this invalidates all iterators
 * pointing into padded.
 *
 * Throw a std::runtime_error if an error is reported
 * by the wrapped libsodium function.
 *
 * Wrapped libsodium function:
 *     sodium_unpad()
 **/

template<typename BT = bytes>
void
unpad_inplace(BT& padded, const size_t blocksize)
{
    std::size_t unpadded_buflen_p;

    int rc = sodium_unpad(&unpadded_buflen_p,
                          reinterpret_cast<const unsigned char*>(padded.data()),
                          padded.size(),
                          blocksize);
    if (rc != 0)
        throw std::runtime_error("sodium::unpad_inplace() failed");

    // XXX we don't explicitely zero-out the pad
    // before throwing it away:

    padded.resize(unpadded_buflen_p);
}

} // namespace sodium
