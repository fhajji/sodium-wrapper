// secretstream_xchacha20_poly1305.h -- secret stream with xchacha20-poly1305
// construction
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

#include <sodium.h>

/**
 * Interchangeable secretstream encrypt/decrypt types.
 *
 * These types are meant to be used as a template argument
 * in sodium::secretstream (see secretstream.h).
 *
 * sodium::secretstream_xchacha20_poly1305 implements the
 * XChacha20-Poly1305 secretstream construction scheme.
 *
 * This is currently the recommended best and most secure scheme.
 * It is also the only one implemented by libsodium's
 * secretstream API as of 1.0.16.
 *
 * Limits:
 *   "There are no practical limits to the total length of the stream,
 *    or to the total number of individual messages." -- libsodium's docs.
 **/

namespace sodium {

class secretstream_xchacha20_poly1305
{
  public:
    constexpr static const char* construction_name =
      "secretstream_xchacha20_poly1305";

    static constexpr std::size_t ABYTES =
      crypto_secretstream_xchacha20poly1305_ABYTES;
    static constexpr std::size_t HEADERBYTES =
      crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    static constexpr std::size_t KEYBYTES =
      crypto_secretstream_xchacha20poly1305_KEYBYTES;
    static constexpr std::size_t MESSAGEBYTES_MAX =
      crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;

    static constexpr unsigned char TAG_MESSAGE =
      crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    static constexpr unsigned char TAG_PUSH =
      crypto_secretstream_xchacha20poly1305_TAG_PUSH;
    static constexpr unsigned char TAG_REKEY =
      crypto_secretstream_xchacha20poly1305_TAG_REKEY;
    static constexpr unsigned char TAG_FINAL =
      crypto_secretstream_xchacha20poly1305_TAG_FINAL;

    using state_type = crypto_secretstream_xchacha20poly1305_state;

    static int init_push(state_type* state,
                         unsigned char header[HEADERBYTES],
                         const unsigned char k[KEYBYTES])
    {
        return ::crypto_secretstream_xchacha20poly1305_init_push(
          state, header, k);
    }

    static int push(state_type* state,
                    unsigned char* c,
                    unsigned long long* clen_p,
                    const unsigned char* m,
                    unsigned long long mlen,
                    const unsigned char* ad,
                    unsigned long long adlen,
                    unsigned char tag)
    {
        return ::crypto_secretstream_xchacha20poly1305_push(
          state, c, clen_p, m, mlen, ad, adlen, tag);
    }

    static int init_pull(state_type* state,
                         const unsigned char header[HEADERBYTES],
                         const unsigned char k[KEYBYTES])
    {
        return ::crypto_secretstream_xchacha20poly1305_init_pull(
          state, header, k);
    }

    static int pull(state_type* state,
                    unsigned char* m,
                    unsigned long long* mlen_p,
                    unsigned char* tag_p,
                    const unsigned char* c,
                    unsigned long long clen,
                    const unsigned char* ad,
                    unsigned long long adlen)
    {
        return ::crypto_secretstream_xchacha20poly1305_pull(
          state, m, mlen_p, tag_p, c, clen, ad, adlen);
    }

    static void rekey(state_type* state)
    {
        ::crypto_secretstream_xchacha20poly1305_rekey(state);
    }
};

} // namespace sodium
