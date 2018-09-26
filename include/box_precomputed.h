// box_precomputed.h -- PK enc/dec with MAC, with precomputed shared key
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
#include "keypair.h"
#include "nonce.h"

#include <stdexcept>

#include <sodium.h>

namespace sodium {

template<typename BT = bytes>
class box_precomputed
{

  public:
    static constexpr unsigned int NONCESIZE = crypto_box_NONCEBYTES;
    static constexpr std::size_t KEYSIZE_PUBLIC_KEY =
      keypair<BT>::KEYSIZE_PUBLIC_KEY;
    static constexpr std::size_t KEYSIZE_PRIVATE_KEY =
      keypair<BT>::KEYSIZE_PRIVATE_KEY;
    static constexpr std::size_t KEYSIZE_SHAREDKEY = crypto_box_BEFORENMBYTES;
    static constexpr std::size_t MACSIZE = crypto_box_MACBYTES;

    using private_key_type = typename keypair<BT>::private_key_type;
    using public_key_type = typename keypair<BT>::public_key_type;
    using nonce_type = nonce<NONCESIZE>;

    /**
     * Create and store an internal shared key built out of a
     * private key and a public key.
     *
     * The private and the public key need not be related, i.e. they
     * need not belong to the same keypair and need not necessarily
     * be generated as a pair by the underlying libsodium function(s)
     * crypto_box_[seed_]keypair().
     *
     * This shared key will be used by the sender to efficiently encrypt
     * and sign multiple plaintexts to the recipient using the encrypt()
     * member function (assuming the public key is the recipient's;
     * and the private key is the sender's).
     *
     * In the other direction, this shared key will be used by the
     * recipient to efficiently decrypt and verify the signature of
     * multiple ciphertexts from the sender (assuming the public key
     * is the sender's, and the private key is the recipient's).
     *
     * public_key, the public key, must be KEYSIZE_PUBLIC_KEY bytes long.
     *
     * If the size of the key isn't correct, the constructor
     * will throw a std::runtime_error.
     **/

    box_precomputed(const private_key_type& private_key,
                    const public_key_type& public_key)
      : shared_key_(false)
      , shared_key_ready_(false)
    {
        set_shared_key(private_key, public_key);
    }

    box_precomputed(const keypair<BT>& keypair)
      : shared_key_(false)
      , shared_key_ready_(false)
    {
        set_shared_key(keypair.private_key(), keypair.public_key());
    }

    /**
     * Copy and move constructors
     **/

    template<typename U>
    box_precomputed(const box_precomputed<U>& other)
      : shared_key_(other.shared_key_)
      , shared_key_ready_(other.shared_key_ready_)
    {}

    template<typename U>
    box_precomputed(box_precomputed<U>&& other)
      : shared_key_(std::move(other.shared_key_))
      , shared_key_ready_(other.shared_key_ready_)
    {
        other.shared_key_ready_ = false;
    }

    /**
     * Change the shared key by setting it so that it is built out of
     * the public key public_key, and the private key private_key.
     *
     * public_key  must be KEYSIZE_PUBLIC_KEY  bytes long.
     *
     * If the size of the key isn't correct, this function will throw
     * a std::runtime_error and the old shared key (if any) will remain
     * unchanged.
     *
     * If the underlying libsodium function crypto_box_beforenm()
     * returns -1, we throw a std::runtime_error as well, and the state
     * of the shared key is undefined.
     **/

    void set_shared_key(const private_key_type& private_key,
                        const public_key_type& public_key)
    {
        // some sanity checks before we get started
        if (public_key.size() != KEYSIZE_PUBLIC_KEY)
            throw std::runtime_error{ "sodium::box_precomputed::set_shared_key("
                                      ") wrong public_key size" };

        // now, ready to go
        shared_key_.readwrite();
        if (crypto_box_beforenm(
              shared_key_.setdata(),
              reinterpret_cast<const unsigned char*>(public_key.data()),
              reinterpret_cast<const unsigned char*>(private_key.data())) ==
            -1) {
            shared_key_ready_ = false; // XXX: undefined?
            throw std::runtime_error{ "sodium::box_precomputed::set_shared_key("
                                      ") crypto_box_beforenm() -1" };
        }
        shared_key_.readonly();
        shared_key_ready_ = true;
    }

    // XXX add set_shared_key(const keypair &)...

    /**
     * Destroy the shared key by zeroing its contents after it is no
     * longer needed.
     *
     * Normally, you don't need to call this function directly, because
     * the shared key will destroy itself anyway when this CryptorMultiPK
     * object goes out of scope.
     **/

    void destroy_shared_key()
    {
        shared_key_.destroy();
        shared_key_ready_ = false;
    }

    /**
     * Encrypt and sign the plaintext using the precomputed shared key
     * which contains the recipient's public key (used for encryption)
     * and the sender's private key (used for signing); and a nonce.
     *
     * Compute an authentication tag MAC as well. Return (MAC ||
     * ciphertext); i.e. ciphertext prepended by MAC.
     *
     * Any modification of the returned (MAC || ciphertext) will render
     * decryption impossible.
     *
     * The nonce is public and can be sent along the (MAC ||
     * ciphertext). The private key / shared key are private and MUST
     * NOT be sent over the channel. The public key is intended to be
     * widely known, even by attackers.
     *
     * To thwart Man-in-the-Middle attacks, it is the responsibility of
     * the recipient to verify (by other means, like certificates, web
     * of trust, etc.) that the public key of the sender does indeed
     * belong to the _real_ sender of the message. This is NOT ensured by
     * this function here.
     *
     * The encrypt() function can be _efficiently_ used repeately by the
     * sender with the same shared key to send multiple messages to the
     * same recipient, but you MUST then make sure never to reuse the
     * same nonce. The easiest way to achieve this is to increment nonce
     * after or prior to each encrypt() invocation.
     *
     * The (MAC || ciphertext) size is
     *    MACSIZE + plaintext.size()
     * bytes long.
     *
     * encrypt() will throw a std::runtime_error if
     *  - the shared key is not ready
     **/

    BT encrypt(const BT& plaintext, const nonce_type& nonce)
    {
        // some sanity checks before we start
        if (!shared_key_ready_)
            throw std::runtime_error{
                "sodium::box_precomputed::encrypt() shared key not ready"
            };

        // make space for ciphertext, i.e. for (MAC || encrypted)
        BT ciphertext(MACSIZE + plaintext.size());

        // and now, encrypt!
        if (crypto_box_easy_afternm(
              reinterpret_cast<unsigned char*>(ciphertext.data()),
              reinterpret_cast<const unsigned char*>(plaintext.data()),
              plaintext.size(),
              nonce.data(),
              reinterpret_cast<const unsigned char*>(shared_key_.data())) == -1)
            throw std::runtime_error{ "sodium::box_precomputed::encrypt() "
                                      "crypto_box_easy_afternm() -1" };

        return ciphertext; // move semantics
    }

    /**
     * Detached version.
     *
     * XXX Document me
     **/

    BT encrypt(const BT& plaintext, const nonce_type& nonce, BT& mac)
    {
        // some sanity checks before we start
        if (!shared_key_ready_)
            throw std::runtime_error{
                "sodium::box_precomputed::encrypt() shared key not ready"
            };
        if (mac.size() != MACSIZE)
            throw std::runtime_error{
                "sodium::box_precomputed::encrypt() wrong mac size"
            };

        // make space for ciphertext, without MAC
        BT ciphertext(plaintext.size());

        // and now, encrypt!
        if (crypto_box_detached_afternm(
              reinterpret_cast<unsigned char*>(ciphertext.data()),
              reinterpret_cast<unsigned char*>(mac.data()),
              reinterpret_cast<const unsigned char*>(plaintext.data()),
              plaintext.size(),
              nonce.data(),
              reinterpret_cast<const unsigned char*>(shared_key_.data())) == -1)
            throw std::runtime_error{ "sodium::box_precomputed::encrypt() "
                                      "crypto_box_easy_afternm() -1" };

        return ciphertext; // move semantics, mac returned via reference
    }

    /**
     * Decrypt and verify the signature of the ciphertext using the
     * precomputed shared key which contains the recipient's private key
     * (used for decryption) and the sender's public key (used for
     * signing); and a nonce. Verify also the MAC within the
     * ciphertext. Return decrypted plaintext.
     *
     * If the ciphertext or the MAC have been tampered with, or if
     * the signature doesn't verify (e.g. because the sender isn't
     * the one who she claims to be), decryption will fail and
     * this function with throw a std::runtime_error.
     *
     * The decrypt() function can be _efficiently_ used repeatedly
     * with the same shared key to decrypt multiple messages from
     * the same sender.
     *
     * This function will also throw a std::runtime_error if, among others:
     *  - the size of the ciphertext_with_mac is not at least MACSIZE
     *  - decryption failed (e.g. because the shared key doesn't match)
     *  - the shared key isn't ready
     **/

    BT decrypt(const BT& ciphertext_with_mac, const nonce_type& nonce)
    {
        // some sanity checks before we start
        if (ciphertext_with_mac.size() < MACSIZE)
            throw std::runtime_error{ "sodium::box_precomputed::decrypt() "
                                      "ciphertext too small for even for MAC" };
        if (!shared_key_ready_)
            throw std::runtime_error{
                "sodium::box_precomputed::decrypt() shared key not ready"
            };

        // make space for decrypted text
        BT decrypted(ciphertext_with_mac.size() - MACSIZE);

        // and now, decrypt!
        if (crypto_box_open_easy_afternm(
              reinterpret_cast<unsigned char*>(decrypted.data()),
              reinterpret_cast<const unsigned char*>(
                ciphertext_with_mac.data()),
              ciphertext_with_mac.size(),
              nonce.data(),
              reinterpret_cast<const unsigned char*>(shared_key_.data())) == -1)
            throw std::runtime_error{
                "sodium::box_precomputed::decrypt() decryption failed"
            };

        return decrypted; // move semantics
    }

    /**
     * Detached version
     *
     * XXX Document me (yada, yada, yada...)
     **/

    BT decrypt(const BT& ciphertext, const nonce_type& nonce, const BT& mac)
    {
        // some sanity checks before we start
        if (mac.size() != MACSIZE)
            throw std::runtime_error{
                "sodium::box_precomputed::decrypt() wrong mac size"
            };
        if (!shared_key_ready_)
            throw std::runtime_error{
                "sodium::box_precomputed::decrypt() shared key not ready"
            };

        // make space for decrypted text
        BT decrypted(ciphertext.size());

        // and now, decrypt!
        if (crypto_box_open_detached_afternm(
              reinterpret_cast<unsigned char*>(decrypted.data()),
              reinterpret_cast<const unsigned char*>(ciphertext.data()),
              reinterpret_cast<const unsigned char*>(mac.data()),
              ciphertext.size(),
              nonce.data(),
              reinterpret_cast<const unsigned char*>(shared_key_.data())) == -1)
            throw std::runtime_error{
                "sodium::box_precomputed::decrypt() decryption failed"
            };

        return decrypted; // move semantics
    }

  private:
    key<KEYSIZE_SHAREDKEY> shared_key_;
    bool shared_key_ready_;
};

} // namespace sodium
