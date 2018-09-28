// verifier.h -- Public-key signatures / verification
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

#include <sodium.h>
#include <stdexcept>

namespace sodium {

template<typename BT = bytes>
class verifier
{

    /**
     * The sodium::verifier class provides verify() functions
     * for a receiver to verify the origin and authenticity of
     * messages signed with class sodium::signer, using the
     * public key of the sender.
     *
     * There are two APIs here: verify() uses the combined mode
     * where the signature is prepended to the message like this:
     *   (signature || message)
     * and verify_detach() where the signature is provided
     * separately from the plaintext for applications
     * that need to store them in different locations.
     *
     * The (public) verifying key must have KEYSIZE_PUBLIC_KEY bytes.
     * The user-supplied signature must have SIGNATURE_SIZE bytes.
     **/

  public:
    using bytes_type = BT;
    using keypairsign_type = typename sodium::keypairsign<>;
    using public_key_type = typename keypairsign_type::public_key_type;

    static constexpr std::size_t KEYSIZE_PUBLIC_KEY =
      keypairsign_type::KEYSIZE_PUBLIC_KEY;
    static constexpr std::size_t SIGNATURE_SIZE = crypto_sign_BYTES;

    // A verifier with a user-supplied key (copying version)
    verifier(const public_key_type& key)
      : key_(key)
    {
        // some sanity checks before we get started
        if (key_.size() != KEYSIZE_PUBLIC_KEY) {
            key_.empty();
            throw std::runtime_error{
                "sodium::verifier::verifier(): wrong public key size"
            };
        }
    }

    // A verifier with a user-supplied key (moving version)
    verifier(public_key_type&& key)
      : key_(std::move(key))
    {
        // some sanity checks before we get started
        if (key_.size() != KEYSIZE_PUBLIC_KEY) {
            key_.empty();
            throw std::runtime_error{
                "sodium::verifier::verifier(&&): wrong public key size"
            };
        }
    }

    // A verifier with a user-supplied key (copying version
    // from a key pair
    // DISABLED: In real world, verifier doesn't have access to
    //           verifiee's private key
    // verifier(const keypairsign_type& keypair)
    //   : key_(keypair.public_key())
    // {}

    // A copying constructor
    verifier(const verifier& other)
      : key_(other.key_)
    {}

    // A moving constructor
    verifier(verifier&& other)
      : key_(std::move(other.key_))
    {}

    /**
     * Verify the signature contained in plaintext_with_signature
     * against the saved public key pubkey. On success, return the
     *plaintext without the signature. On failure, throw
     *std::runtime_error.
     *
     * plaintext_with_signature must be (signature || plaintext),
     * with signature being SIGNATURE_SIZE bytes long.
     **/

    BT verify(const BT& plaintext_with_signature)
    {
        // some sanity checks before we get started
        if (plaintext_with_signature.size() < SIGNATURE_SIZE)
            throw std::runtime_error{ "sodium::verifier::verify(): "
                                      "plaintext_with_signature too small "
                                      "for signature" };

        // make space for plaintext without signature
        BT plaintext(plaintext_with_signature.size() - SIGNATURE_SIZE);
        unsigned long long plaintext_size;

        // let's verify signature now!
        if (crypto_sign_open(reinterpret_cast<unsigned char*>(plaintext.data()),
                             &plaintext_size,
                             reinterpret_cast<const unsigned char*>(
                               plaintext_with_signature.data()),
                             plaintext_with_signature.size(),
                             key_.data()) == -1) {
            throw std::runtime_error{
                "sodium::verifier::verify(): signature didn't verify"
            };
        }

        // yet another sanity check
        if (plaintext_size != plaintext_with_signature.size() - SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::verifier::verify(): wrong plaintext size"
            };

        return plaintext; // per move semantics
    }

    /**
     * Verify the signature of the plaintext against the saved public
     *key. On success, return true. On failure, return false.  If size
     *of signature isn't SIGNATURE_SIZE bytes, throw std::runtime_error.
     **/

    bool verify_detached(const BT& plaintext, const bytes& signature)
    {
        // some sanity checks before we get started
        if (signature.size() != SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::verifier::verify_detached(): wrong signature "
                "size"
            };

        // let's verify the detached signature now!
        return crypto_sign_verify_detached(
                 signature.data(),
                 reinterpret_cast<const unsigned char*>(plaintext.data()),
                 plaintext.size(),
                 key_.data()) != -1;
    }

  private:
    public_key_type key_;
};

} // namespace sodium
