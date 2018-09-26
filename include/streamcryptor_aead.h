// streamcryptor_aead.h -- Symmetric blockwise stream encryption/decryption (ad
// hoc)
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

#include "aead.h"
#include "common.h"
#include "key.h"
#include "nonce.h"

#include <istream>
#include <ostream>
#include <stdexcept>

#include <sodium.h>

/**
 * Deprecated: use sodium::secretstream instead.
 *
 * Currently only used in sodiumtester. It will be deleted
 * as soom as it is re-implemented using sodium::secretstream.
 **/

namespace sodium {

template<typename BT = bytes>
class streamcryptor_aead
{
  public:
    /**
     * We encrypt with AEAD.
     **/
    constexpr static std::size_t KEYSIZE = aead<BT>::KEYSIZE;

    /**
     * Each block of plaintext will be encrypted to a block of the same
     * size of ciphertext, combined with a MAC of size MACSIZE.  Note
     * that the total blocksize of the (MAC || ciphertext)s will be
     * MACSIZE + plaintext.size() for each block.
     **/
    constexpr static std::size_t MACSIZE = aead<BT>::MACSIZE;

    /**
     * A StreamCryptor will encrypt/decrypt streams blockwise using a
     * CryptorAEAD as the crypto engine.
     *
     * Each block of size blocksize from the input stream is encrypted
     * or decrypted in turn, using Authenticated Encryption with Added
     * Data to detect tampering of the ciphertext. The added plain text
     * data is for each block an empty header. Each block is encrypted
     * with the same key, but with a monotonically incremented nonce.
     *
     * The constructor saves a copy of the key of KEYSIZE bytes, and a
     * copy of a CryptorAEAD::nonce_type nonce for later use in its
     * internal state. Furthermore, it also saves the desired blocksize
     * that will be used for both encryption and decryption of the
     * streams.
     *
     * If the key size isn't correct, or the blocksize doesn't make sense,
     * the constructor throws a std::runtime_error.
     **/

    streamcryptor_aead(const typename aead<BT>::key_type& key,
                       const typename aead<BT>::nonce_type& nonce,
                       const std::size_t blocksize)
      : sc_aead_{ aead<>(key) }
      , nonce_{ nonce }
      , header_{}
      , blocksize_{ blocksize }
    {
        // some sanity checks, before we start
        if (blocksize < 1)
            throw std::runtime_error{ "sodium::streamcryptor_aead::"
                                      "streamcryptor_aead(): wrong blocksize" };
    }

    /**
     * Encrypt data read from input stream istr in a blockwise fashion,
     * writing (MAC || ciphertext) blocks to the output stream ostr.
     *
     * The input stream istr is read blockwise in chunks of size blocksize,
     * where blocksize has been passed in the constructor. The final block
     * by have less than blocksize bytes.
     *
     * The encyption is performed by the aead crypto engine, using
     * the saved key, and a running nonce that starts with the initial
     * nonce passed at construction time, and whose copy is incremented
     * for each chunk.
     *
     * As soon as a chunk has been encrypted, it is written to the
     * output stream ostr.
     *
     * Note that each written chunk contains both the ciphertext for the
     * original chunk read from istr, as well as the authenticated MAC
     * of size MACSIZE, computed from both the ciphertext, as well as
     * from an empty plaintext header.  This additional MAC occurs every
     * chunk, and helps the decrypt() function verify the integrity of
     * the chunk (and MAC), should it have been tampered with.
     *
     * The saved nonce is not affected by the incrementing of the
     * running nonce. It can thus be reused to decrypt() a stream
     * encrypt()ed by *this.
     *
     * If an error occurs while writing to ostr, throw a std::runtime_error.
     **/

    void encrypt(std::istream& istr, std::ostream& ostr)
    {
        BT plaintext(blocksize_, '\0');
        typename aead<BT>::nonce_type running_nonce{ nonce_ };

        while (
          istr.read(reinterpret_cast<char*>(plaintext.data()), blocksize_)) {
            BT ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
            running_nonce.increment();

            ostr.write(reinterpret_cast<char*>(ciphertext.data()),
                       ciphertext.size());
            if (!ostr)
                throw std::runtime_error{
                    "sodium::streamcryptor_aead::encrypt() error writing full "
                    "chunk to stream"
                };
        }

        // check to see if we've read a final partial chunk
        std::size_t s = static_cast<std::size_t>(istr.gcount());
        if (s != 0) {
            if (s != plaintext.size())
                plaintext.resize(s);

            BT ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
            // running_nonce.increment() not needed anymore...
            ostr.write(reinterpret_cast<char*>(ciphertext.data()),
                       ciphertext.size());
            if (!ostr)
                throw std::runtime_error{
                    "sodium::streamcryptor_aead::encrypt() error writing final "
                    "chunk to stream"
                };
        }
    }

    /**
     * Decrypt data read from input stream istr in a blockwise fashion,
     * writing the plaintext to the output stream ostr.
     *
     * The input stream istr is assumed to have been generated by encrypt()
     * using the same key, (initial) nonce, and blocksize. Otherweise,
     * decryption will fail and a std::runtime_error will the thrown.
     *
     * The input stream istr is read blockwise in chunks of size MACSIZE
     * + blocksize, because each chunk in the encrypted stream is
     * assumed to have been combined with an authenticating MAC, i.e. to
     * be of the form (MAC || ciphertext).  The final block may have
     * less than MACSIZE + blocksize bytes, but should have at least
     * MACSIZE bytes left.
     *
     * The decryption is attempted by the aead crypto engine, using
     * the saved key, and a running nonce that starts with the initial
     * nonce passed at construction time, and whose copy is incremented
     * with each chunk.
     *
     * As soon as a chunk has been decrypted, it is written to the output
     * stream ostr.
     *
     * Decryption can fail if
     *   - the key was wrong
     *   - the initial nonce was wrong
     *   - the blocksize was wrong
     *   - the input stream wasn't encrypted with encrypt()
     *   - one or more (MAC || ciphertext) chunks have been tampered with
     * In that case, throw a std::runtime_error and stop writing to ostr.
     * No strong guarantee w.r.t. ostr.
     *
     * The saved nonce is unaffected by the incrementing of the running
     * nonce during decryption.
     **/

    void decrypt(std::istream& istr, std::ostream& ostr)
    {
        BT ciphertext(MACSIZE + blocksize_, '\0');
        typename aead<BT>::nonce_type running_nonce{
            nonce_
        }; // restart with saved nonce_

        while (istr.read(reinterpret_cast<char*>(ciphertext.data()),
                         MACSIZE + blocksize_)) {
            // we've got a whole MACSIZE + blocksize_ chunk
            BT plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
            running_nonce.increment();

            ostr.write(reinterpret_cast<char*>(plaintext.data()),
                       plaintext.size());
            if (!ostr)
                throw std::runtime_error{
                    "sodium::streamcryptor_aead::decrypt() error writing full "
                    "chunk to stream"
                };
        }

        // check to see if we've read a final partial chunk
        std::size_t s = static_cast<std::size_t>(istr.gcount());
        if (s != 0) {
            // we've got a partial chunk
            if (s != ciphertext.size())
                ciphertext.resize(s);

            BT plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
            // no need to running_nonce.increment() anymore...

            ostr.write(reinterpret_cast<char*>(plaintext.data()),
                       plaintext.size());
            if (!ostr)
                throw std::runtime_error{
                    "sodium::streamcryptor_aead::decrypt() error writing final "
                    "chunk to stream"
                };
        }
    }

  private:
    aead<BT> sc_aead_;
    typename aead<BT>::nonce_type nonce_;
    BT header_;
    std::size_t blocksize_;
};

} // namespace sodium
