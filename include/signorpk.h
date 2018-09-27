// signorpk.h -- Public-key signatures / verification
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

class SignorPK
{

    /**
     * The sodium::SignorPK class provides sign() and verify() functions
     * for a sender to sign plaintext messages with her private key; and
     * for a receiver to verify the origin and authenticity of those
     * messages with the public key of the sender.
     *
     * Upon signing, the signature is prepended to the _plaintext_
     * message. Note that the message itself is NOT encrypted or
     * changted in any way. Use other functions / classes if you need
     * confidentiality.
     *
     * There are two APIs here: sign() and verify() use the combined mode
     * where the signature is prepended to the message like this:
     *   (signature || message)
     * and sign_detach() and verify_detach() where the signature is
     * returned resp. provided separately from the plaintext for applications
     * that need to store them in different locations.
     *
     * There are also two different ways to provide the keys for
     * signing and verification: individually, or combined as a
     * pair of public/private _signing_ keys. Because signing keys
     * have a different number of bytes than encryption keys, a
     * Sodium::KeyPairSign instead of a Sodium::KeyPair is required
     * in that case.
     *
     * The (private) signing key must have KEYSIZE_PRIVKEY bytes
     * The (public) verifying key must have KEYSIZE_PUBKEY bytes
     * Both can be created with libsodium's crypto_sign_[seed]_keypair()
     * primitives, or, much more conveniently, with Sodium::KeyPairSign.
     **/

  public:
    static constexpr std::size_t KEYSIZE_PUBKEY =
      sodium::keypairsign<>::KEYSIZE_PUBLIC_KEY;
    static constexpr std::size_t KEYSIZE_PRIVKEY =
      sodium::keypairsign<>::KEYSIZE_PRIVATE_KEY;
    static constexpr std::size_t SIGNATURE_SIZE = crypto_sign_BYTES;

    using privkey_type = key<KEYSIZE_PRIVKEY>;

    /**
     * Sign the plaintext with the private key privkey.  Return
     * (signature || plaintext), where signature is SIGNATURE_SIZE bytes
     * long.
     **/

    bytes sign(const bytes& plaintext, const privkey_type& privkey)
    {
        bytes plaintext_signed(SIGNATURE_SIZE + plaintext.size());
        if (crypto_sign(plaintext_signed.data(),
                        NULL,
                        plaintext.data(),
                        plaintext.size(),
                        privkey.data()) == -1)
            throw std::runtime_error{
                "sodium::SignorPK::sign(): crypto_sign() -1"
            };

        return plaintext_signed; // per move semantics
    }

    /**
     * Sign the plaintext with the private key part of the keypair.
     * Return (signature || plaintext), where signature is
     * SIGNATURE_SIZE bytes long.
     **/
    bytes sign(const bytes& plaintext, const keypairsign<>& keypair)
    {
        return sign(plaintext, keypair.private_key());
    }

    /**
     * Sign the plaintext with the private key privkey. Return the
     * signature, which is SIGNATURE_SIZE bytes long.
     **/
    bytes sign_detached(const bytes& plaintext, const privkey_type& privkey)
    {
        bytes signature(SIGNATURE_SIZE);
        unsigned long long signature_size;

        if (crypto_sign_detached(signature.data(),
                                 &signature_size,
                                 plaintext.data(),
                                 plaintext.size(),
                                 privkey.data()) == -1)
            throw std::runtime_error{ "sodium::SignorPK::sign_detached(): "
                                      "crypto_sign_detached() -1" };

        // sanity check
        if (signature_size != SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::SignorPK::sign_detached(): wrong signature size"
            };

        return signature; // per move semantics
    }

    /**
     * Sign the plaintext with the private key part of the keypair.
     * Return the signature, which is SIGNATURE_SIZE bytes long.
     **/
    bytes sign_detached(const bytes& plaintext, const keypairsign<>& keypair)
    {
        return sign_detached(plaintext, keypair.private_key());
    }

    /**
     * Verify the signature contained in plaintext_with_signature
     * against the public key pubkey. On success, return the plaintext
     * without the signature. On failure, throw std::runtime_error.
     *
     * plaintext_with_signature must be (signature || plaintext),
     * with signature being SIGNATURE_SIZE bytes long.
     **/

    bytes verify(const bytes& plaintext_with_signature, const bytes& pubkey)
    {
        // some sanity checks before we get started
        if (pubkey.size() != KEYSIZE_PUBKEY)
            throw std::runtime_error{
                "sodium::SignorPK::verify(): wrong pubkey size"
            };
        if (plaintext_with_signature.size() < SIGNATURE_SIZE)
            throw std::runtime_error{ "sodium::SignorPK::verify(): "
                                      "plaintext_with_signature too small "
                                      "for signature" };

        // make space for plaintext without signature
        bytes plaintext(plaintext_with_signature.size() - SIGNATURE_SIZE);
        unsigned long long plaintext_size;

        // let's verify signature now!
        if (crypto_sign_open(plaintext.data(),
                             &plaintext_size,
                             plaintext_with_signature.data(),
                             plaintext_with_signature.size(),
                             pubkey.data()) == -1) {
            throw std::runtime_error{
                "sodium::SignorPK::verify(): signature didn't verify"
            };
        }

        // yet another sanity check
        if (plaintext_size != plaintext_with_signature.size() - SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::SignorPK::verify(): wrong plaintext size"
            };

        return plaintext; // per move semantics
    }

    /**
     * Verify the signature contained in plaintext_with_signature
     * against the public key part of the keypair. On success, return
     * the plaintext without the signature. On failure, throw a
     * std::runtime_error.
     *
     * plaintext_with_signature must be (signature || plaintext),
     * with signature being SIGNATURE_SIZE bytes long.
     **/

    bytes verify(const bytes& plaintext_with_signature,
                 const keypairsign<>& keypair)
    {
        return verify(plaintext_with_signature, keypair.public_key());
    }

    /**
     * Verify the signature of the plaintext against the pubkey.  On
     * success, return true. On failure, return false.  If size of
     * signature isn't SIGNATURE_SIZE bytes, throw std::runtime_error.
     **/

    bool verify_detached(const bytes& plaintext,
                         const bytes& signature,
                         const bytes& pubkey)
    {
        // some sanity checks before we get started
        if (pubkey.size() != KEYSIZE_PUBKEY)
            throw std::runtime_error{
                "sodium::SignorPK::verify_detached(): wrong pubkey size"
            };
        if (signature.size() != SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::SignorPK::verify_detached(): wrong signature size"
            };

        // let's verify the detached signature now!
        return crypto_sign_verify_detached(signature.data(),
                                           plaintext.data(),
                                           plaintext.size(),
                                           pubkey.data()) != -1;
    }

    /**
     * Verify the signature of the plaintext against the public key part
     * of the keypair. On success, return true. On failure, return
     * false.  If size of signature isn't SIGNATURE_SIZE bytes, throw
     * std::runtime_error.
     **/
    bool verify_detached(const bytes& plaintext,
                         const bytes& signature,
                         const keypairsign<>& keypair)
    {
        return verify_detached(plaintext, signature, keypair.public_key());
    }
};

} // namespace sodium
