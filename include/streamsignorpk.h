// streamsignorpk.h -- Public-key signing streaming interface
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
#include "key.h"
#include "keypairsign.h"

#include <istream>
#include <ostream>
#include <stdexcept>

#include <sodium.h>

namespace sodium {

class StreamSignorPK
{
  public:
    static constexpr std::size_t KEYSIZE_PRIVKEY =
      sodium::keypairsign<>::KEYSIZE_PRIVATE_KEY;
    static constexpr std::size_t SIGNATURE_SIZE = crypto_sign_BYTES;

    using privkey_type = key<KEYSIZE_PRIVKEY>;

    /**
     * A StreamSignorPK will sign streams of potentially unlimited length
     * using the crypto_sign_{init,update,final_create}() libsodium API.
     *
     * The stream will be read in a blockwise fashion with blocks
     * of size at most blocksize bytes.
     *
     * The constructor takes a private _signing_ Key of size
     * KEYSIZE_PRIVKEY bytes.
     **/

    StreamSignorPK(const privkey_type& privkey, const std::size_t blocksize)
      : privkey_{ privkey }
      , blocksize_{ blocksize }
    {
        if (blocksize < 1)
            throw std::runtime_error{
                "sodium::StreamSignorPK() wrong blocksize"
            };

        crypto_sign_init(&state_);
    }

    /**
     * A StreamSignorPK will sign streams of potentially unlimited length
     * using the crypto_sign_{init,update,final_create}() libsodium API.
     *
     * The stream will be read in a blockwise fashion with blocks
     * of size at most blocksize bytes.
     *
     * The constructor takes a KeyPairSign and uses the privkey part of
     * it to sign the messages.
     **/
    StreamSignorPK(const keypairsign<>& keypair, const std::size_t blocksize)
      : privkey_{ keypair.private_key() }
      , blocksize_{ blocksize }
    {
        if (blocksize < 1)
            throw std::runtime_error{
                "sodium::StreamSignorPK() wrong blocksize"
            };

        crypto_sign_init(&state_);
    }

    /**
     * Sign the data provided by the std::istream istr, using the private
     * signing key provided by the constructor. As soon as the stream
     * reaches eof(), the signature is returned, and the state is reset.
     *
     * The stream is read() blockwise, using blocks of size up to
     * blocksize_ bytes.
     *
     * It is possible to call sign() multiple times.
     *
     * sign() will throw a std::runtime_error if the istr fails.
     **/

    bytes sign(std::istream& istr)
    {
        bytes plaintext(blocksize_, '\0');

        while (
          istr.read(reinterpret_cast<char*>(plaintext.data()), blocksize_)) {
            // read a whole block of blocksize_ chars (bytes)
            crypto_sign_update(&state_, plaintext.data(), plaintext.size());
        }

        // check to see if we've read a final partial chunk
        std::size_t s = static_cast<std::size_t>(istr.gcount());
        if (s != 0) {
            if (s != plaintext.size())
                plaintext.resize(s);

            crypto_sign_update(&state_, plaintext.data(), plaintext.size());
        }

        // finalize the signature
        bytes signature(SIGNATURE_SIZE);
        crypto_sign_final_create(
          &state_, signature.data(), NULL, privkey_.data());

        // reset the state for next invocation of sign()
        crypto_sign_init(&state_);

        return signature; // using move semantics
    }

  private:
    privkey_type privkey_;
    crypto_sign_state state_;
    std::size_t blocksize_;
};

} // namespace sodium
