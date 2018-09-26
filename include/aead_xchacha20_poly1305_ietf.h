// aead_xchacha20_poly1305_ietf.h -- IETF xchacha20-poly1305 construction
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
 * Interchangeable AEAD encrypt/decrypt types.
 *
 * These types are meant to be used as a template argument
 * in sodium::aead (see aead.h).
 *
 * sodium::aead_xchacha20_poly1305_ietf implements the
 * XChacha20-Poly1305 AEAD construction scheme.
 *
 * This is currently the recommended best and most secure scheme.
 *
 * Limits:
 *   Maximum number of bytes per message: practically unlimited, ~2^64.
 *   Maximum number of messages without re-keying: practically unlimited.
 *   Nonces (192-bit) can be selected randomly (use sodium::randombytes_buf)
 *     or incremented.
 **/

namespace sodium {

class aead_xchacha20_poly1305_ietf
{
  public:
    constexpr static const char* construction_name = "xchacha20_poly1305_ietf";

    static int encrypt(unsigned char* c,
                       unsigned long long* clen,
                       const unsigned char* m,
                       unsigned long long mlen,
                       const unsigned char* ad,
                       unsigned long long adlen,
                       const unsigned char* nsec,
                       const unsigned char* npub,
                       const unsigned char* k)
    {
        return crypto_aead_xchacha20poly1305_ietf_encrypt(
          c, clen, m, mlen, ad, adlen, nsec, npub, k);
    };

    static int decrypt(unsigned char* m,
                       unsigned long long* mlen,
                       unsigned char* nsec,
                       const unsigned char* c,
                       unsigned long long clen,
                       const unsigned char* ad,
                       unsigned long long adlen,
                       const unsigned char* npub,
                       const unsigned char* k)
    {
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
          m, mlen, nsec, c, clen, ad, adlen, npub, k);
    };

    static int encrypt_detached(unsigned char* c,
                                unsigned char* mac,
                                unsigned long long* maclen_p,
                                const unsigned char* m,
                                unsigned long long mlen,
                                const unsigned char* ad,
                                unsigned long long adlen,
                                const unsigned char* nsec,
                                const unsigned char* npub,
                                const unsigned char* k)
    {
        return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
          c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    };

    static int decrypt_detached(unsigned char* m,
                                unsigned char* nsec,
                                const unsigned char* c,
                                unsigned long long clen,
                                const unsigned char* mac,
                                const unsigned char* ad,
                                unsigned long long adlen,
                                const unsigned char* npub,
                                const unsigned char* k)
    {
        return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
          m, nsec, c, clen, mac, ad, adlen, npub, k);
    };

    static constexpr std::size_t KEYBYTES =
      crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
    static constexpr std::size_t NPUBBYTES =
      crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
    static constexpr std::size_t ABYTES =
      crypto_aead_xchacha20poly1305_IETF_ABYTES;
};

} // namespace sodium
