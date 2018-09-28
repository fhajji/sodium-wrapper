// signer.h -- Public-key signatures / verification
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
class signer
{

    /**
     * The sodium::signer class provides sign() functions
     * for a sender to sign plaintext messages with her private key,
     * so that a receiver can verify the origin and authenticity of those
     * messages with the public key of the sender, using sodium::verifier.
     *
     * Upon signing, the signature is prepended to the _plaintext_
     * message. Note that the message itself is NOT encrypted or
     * changted in any way. Use other functions / classes if you need
     * confidentiality.
     *
     * There are two APIs here: sign() uses the combined mode
     * where the signature is prepended to the message like this:
     *   (signature || message)
     * and sign_detach() where the signature is returned separately
     * from the plaintext for applications that need to store them
     * in different locations.
     *
     * The (private) signing key must have KEYSIZE_PRIVATE_KEY bytes
     * Both private and public keys can be created with libsodium's
     * crypto_sign_[seed]_keypair() primitive, or, more conveniently,
     * with sodium::keypairsign.
     **/

  public:
    using bytes_type = BT;
    using keypairsign_type = typename sodium::keypairsign<>;
    using private_key_type = typename keypairsign_type::private_key_type;

    static constexpr std::size_t KEYSIZE_PRIVATE_KEY =
      keypairsign_type::KEYSIZE_PRIVATE_KEY;
    static constexpr std::size_t SIGNATURE_SIZE = crypto_sign_BYTES;

    // A signer with a user-supplied key (copying version)
    signer(const private_key_type& key)
      : key_(key)
    {}

    // A signer with a user-supplied key (moving version)
    signer(private_key_type&& key)
      : key_(std::move(key))
    {}

    // A signer with a user-supplied key (copying version from
    // a keypairsign<>)
    signer(keypairsign_type& keypair)
      : key_(keypair.private_key())
    {}

    // A copying constructor
    signer(const signer& other)
      : key_(other.key_)
    {}

    // A moving constructor
    signer(signer&& other)
      : key_(std::move(other.key_))
    {}

    /**
     * Sign the plaintext with the saved private key. Return
     * (signature || plaintext), where signature is SIGNATURE_SIZE bytes
     * long.
     **/

    BT sign(const BT& plaintext)
    {
        BT plaintext_signed(SIGNATURE_SIZE + plaintext.size());
        if (crypto_sign(
              reinterpret_cast<unsigned char*>(plaintext_signed.data()),
              NULL,
              reinterpret_cast<const unsigned char*>(plaintext.data()),
              plaintext.size(),
              key_.data()) == -1)
            throw std::runtime_error{
                "sodium::signer::sign(): crypto_sign() -1"
            };

        return plaintext_signed; // per move semantics
    }

    /**
     * Sign the plaintext with the saved private key. Return the
     * signature, which is SIGNATURE_SIZE bytes long.
     **/
    bytes sign_detached(const BT& plaintext)
    {
        bytes signature(SIGNATURE_SIZE);
        unsigned long long signature_size;

        if (crypto_sign_detached(
              signature.data(),
              &signature_size,
              reinterpret_cast<const unsigned char*>(plaintext.data()),
              plaintext.size(),
              key_.data()) == -1)
            throw std::runtime_error{ "sodium::signer::sign_detached(): "
                                      "crypto_sign_detached() -1" };

        // sanity check
        if (signature_size != SIGNATURE_SIZE)
            throw std::runtime_error{
                "sodium::signer::sign_detached(): wrong signature size"
            };

        return signature; // per move semantics
    }

  private:
    private_key_type key_;
};

} // namespace sodium
