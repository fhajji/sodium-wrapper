// key.h -- Sodium Key Wrapper
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

#include "allocator.h"
#include "common.h"
#include "random.h"

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <sodium.h>

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace sodium {

// Some common constants for typical key sizes from <sodium.h>
static constexpr std::size_t KEYSIZE_SECRETBOX = crypto_secretbox_KEYBYTES;
static constexpr std::size_t KEYSIZE_AUTH = crypto_auth_KEYBYTES;
static constexpr std::size_t KEYSIZE_POLY1305 = crypto_onetimeauth_KEYBYTES;
static constexpr std::size_t KEYSIZE_SALT = crypto_pwhash_SALTBYTES;
static constexpr std::size_t KEYSIZE_HASHKEY = crypto_generichash_KEYBYTES;
static constexpr std::size_t KEYSIZE_HASHKEY_MIN =
  crypto_generichash_KEYBYTES_MIN;
static constexpr std::size_t KEYSIZE_HASHKEY_MAX =
  crypto_generichash_KEYBYTES_MAX;
static constexpr std::size_t KEYSIZE_HASHSHORTKEY = crypto_shorthash_KEYBYTES;
static constexpr std::size_t KEYSIZE_CHACHA20 = crypto_stream_chacha20_KEYBYTES;
static constexpr std::size_t KEYSIZE_XCHACHA20 =
  crypto_stream_xchacha20_KEYBYTES;
static constexpr std::size_t KEYSIZE_SALSA20 = crypto_stream_salsa20_KEYBYTES;
static constexpr std::size_t KEYSIZE_XSALSA20 = crypto_stream_KEYBYTES;

template<std::size_t KEYSZ = 0, typename BT = bytes_protected>
class key
{
    /**
     * The class sodium::key<KEYSZ> represents a key used in various
     * functions of the libsodium library.  Key material, being
     * particulary sensitive, is stored in "protected memory" using a
     * special allocator.
     *
     * A key can be
     *   - default-constructed using random data,
     *   - default-constructed but left uninitialized
     *   - derived from a password string and a (hopefully random) salt.
     *
     * A key can be made read-only or non-accessible when no longer
     * needed.  In general, it is a good idea to be as restrictive as
     * possible with key material.
     *
     * When a key goes out of scope, it auto-destructs by zeroing its
     * memory, and eventually releasing the virtual pages too.
     **/

  public:
    /**
     * bytes_type is bytes_protected memory for bytes of key material.
     *   * bytes_protected memory will self-destruct/zero when out-of-scope /
     *throws
     *   * bytes_protected memory can be made readonly or temporarily
     *non-accessible
     *   * bytes_protected memory is stored in virtual pages protected by
     *canary, guard pages, and access to those pages is granted with mprotect().
     **/

    using bytes_type = BT;
    using byte_type =
      typename bytes_type::value_type; // e.g. byte (unsigned char)

    // refuse to compile when not instantiating with bytes_protected
    static_assert(std::is_same<bytes_type, bytes_protected>(),
                  "key<> not in protected memory");

    // The strength of the key derivation efforts for setpass()
    using strength_type = enum class strength_enum { low, medium, high };

    /**
     * Construct a key of size KEYSZ.
     *
     * If bool is true, initialize the key, i.e. fill it with random data
     * generated by initialize(), and then make it readonly().
     *
     * If bool is false, leave the key uninitialized, i.e. in the state
     * as created by the special allocator for protected memory. Leave
     * the key in the readwrite() default for further setpass()...
     **/

    explicit key(bool init = true)
      : keydata_(KEYSZ)
    {
        if (init) {
            initialize();
            readonly();
        }
        // CAREFUL: read/write uninitialized key
    }

    /**
     * Copy constructor for keys
     *
     * Note that copying a key can be expensive, as the underlying keydata_
     * needs to be copied as well, i.e. new bytes_protected virtual pages
     * need to be allocated, mprotect()ed etc.
     *
     * Consider using move semantics/constructor when passing key(s) along
     * for better performance (see below).
     *
     * Note that the copied key will be readwrite(), even if the source
     * was readonly(). If you want a read-only copy, you'll have manually
     * set it to readonly() after it was copy-constructed.
     *
     * If the source key was noaccess(), this copy c'tor will terminate
     * the program.
     **/

    key(const key& other) = default;
    key& operator=(const key& other) = default;

    /**
     * A key can be move-constructed and move-assigned from another
     * existing key, thereby destroying that other key along the way.
     *
     * Move semantics for a key means that the underlying keydata_
     * bytes_type representation won't be unnecessarily duplicated
     * or copied around; saving us from creating virtual pages and
     * mprotect()-ing them when passing key(s) around.
     *
     * For move semantics to take effect, don't forget to use
     * either r-values for key(s) when passing them to functions,
     * or convert key l-values to r-values with std::move().
     *
     * The following constructor / members implement move semantics
     * for keys.
     **/

    key(key&& other) noexcept
      : keydata_(0)
    {
        // temporarily create an empty key with 0 (i.e. keydata_(0))
        // bytes (no allocation in bytes_protected memory at all required)
        // that can be trivially destroyed; and swap that with other, that
        // will then be an empty shell.
        //
        // NOTE: other.size() will, after this, no more be KEYSZ.
        std::swap(this->keydata_, other.keydata_);
    }

    key& operator=(key&& other)
    {
        this->keydata_ = std::move(other.keydata_);
        return *this;
    }

    /**
     * Various libsodium functions used either directly or in
     * the wrappers need access to the bytes stored in the key.
     *
     * data() gives const access to those bytes of which
     * size() bytes are stored in the key.
     *
     * We don't provide mutable access to the bytes by design
     * with this data()/size() interface.
     *
     * The only functions that change those bytes are:
     *   initialize(), destroy(), setpass().
     *
     * !!!! IMPORTANT INVARIANT -- CHECK MANUALLY !!!!
     *
     * Note that we return KEYSZ instead of keydata_.size() in size()
     * so that size() can be declared constexpr and used in
     * static_assert() in callers.  We must make sure that the
     * invariant KEYSZ == keydata_.size() always holds when modifying
     * this class.
     *
     * Even in the move constructor above, this is the case immediately
     * _after_ the constructor has finished constructing *this! (XXX).
     **/

    const byte_type* data() const { return keydata_.data(); }
    constexpr std::size_t size() const { return keydata_.size(); }

    /**
     * Provide mutable access to the bytes of the key, so that users
     * can change / set them from the outside.
     *
     * It is the responsibility of the user to ensure that
     *   - the key is set to readwrite(), if data is to be changed
     *   - no more than [setdata(), setdata()+size()) bytes are changed
     *     (or undefined behavior follows).
     *
     * This function is primarily provided for the classes whose
     * underlying libsodium functions write the bytes of a key directly,
     * like:
     *   - KeyPair
     *   - CryptorMultiPK
     **/

    byte_type* setdata() { return keydata_.data(); }

    /**
     * Derive key material from the string password, and the salt
     * (where salt.size() == KEYSIZE_SALT) and store that key material
     * into this key object's protected readonly() memory.
     *
     * The strength parameter determines how much effort is to be
     * put into the derivation of the key. It can be one of
     *    key<KEYSZ>::strength_type::{low,medium,high}.
     *
     * This function throws a std::runtime_error if the strength parameter
     * or the salt size don't make sense, or if the underlying libsodium
     * derivation function crypto_pwhash() runs out of memory.
     **/

    void setpass(const std::string& password,
                 const bytes& salt,
                 const strength_type strength = strength_type::high)
    {
        // check strength and set appropriate parameters
        std::size_t strength_mem;
        unsigned long long strength_cpu;
        switch (strength) {
            case strength_type::low:
                strength_mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
                strength_cpu = crypto_pwhash_OPSLIMIT_INTERACTIVE;
                break;
            case strength_type::medium:
                strength_mem = crypto_pwhash_MEMLIMIT_MODERATE;
                strength_cpu = crypto_pwhash_OPSLIMIT_MODERATE;
                break;
            case strength_type::high:
                strength_mem = crypto_pwhash_MEMLIMIT_SENSITIVE;
                strength_cpu = crypto_pwhash_OPSLIMIT_SENSITIVE;
                break;
            default:
                throw std::runtime_error{
                    "sodium::key::setpass() wrong strength"
                };
        }

        // check salt length
        if (salt.size() != KEYSIZE_SALT)
            throw std::runtime_error{
                "sodium::key::setpass() wrong salt size"
            };

        // derive a key from the hash of the password, and store it!
        readwrite(); // temporarily unlock the key (if not already)
        if (crypto_pwhash(keydata_.data(),
                          keydata_.size(),
                          password.data(),
                          password.size(),
                          salt.data(),
                          strength_cpu,
                          strength_mem,
                          crypto_pwhash_ALG_DEFAULT) != 0)
            throw std::runtime_error{
                "sodium::key::setpass() crypto_pwhash()"
            };
        readonly(); // relock the key
    }

    /**
     * Initialize, i.e. fill with random data generated with libsodium's
     * function randombytes_buf() the number of bytes already allocated
     * to this key upon construction.
     *
     * You normally don't need to call this function yourself, as it is
     * called by key's constructor. It is provided as a public function
     * nonetheless, should you need to rescramble the key, keeping its
     * size (a rare case).
     *
     * This function will terminate the program if the key is readonly()
     * or noaccess() on systems that enforce mprotect().
     **/

    void initialize() { sodium::randombytes_buf_inplace(keydata_); }

    /**
     * Destroy the bytes stored in protected memory of this key by
     * attempting to zeroing them.
     *
     * A key that has been destroy()ed still holds size() zero-bytes in
     * protected memory, and can thus be reused, i.e. reset by calling
     * e.g. setpass().
     *
     * The key will be destroyed, even if it has been set readonly()
     * or noaccess() previously.
     *
     * You normally don't need to explicitely zero a key, because keys
     * self-destruct (including zeroing their bytes) when they go out
     * of scope. This function is provided in case you need to immediately
     * erase a key anyway (think: Panic Button).
     **/

    void destroy()
    {
        readwrite();
        sodium_memzero(keydata_.data(), keydata_.size());
    }

    /**
     * Mark this key as non-accessible. All attempts to read or write
     * to this key will be caught by the CPU / operating system and
     * will result in abnormal program termination.
     *
     * The protection mechanism works by mprotect()ing the virtual page
     * containing the key bytes accordingly.
     *
     * Note that the key bytes are still available, even when noaccess()
     * has been called. Restore access by calling readonly() or readwrite().
     **/

    void noaccess() { keydata_.get_allocator().noaccess(keydata_.data()); }

    /**
     * Mark this key as read-only. All attemps to write to this key will
     * be caught by the CPU / operating system and will result in abnormal
     * program termination.
     *
     * The protection mechanism works by mprotect()ing the virtual page
     * containing the key bytes accordingly.
     *
     * Note that the key bytes can be made writable by calling readwrite().
     **/

    void readonly() { keydata_.get_allocator().readonly(keydata_.data()); }

    /**
     * Mark this key as read/writable. Useful after it has been previously
     * marked readonly() or noaccess().
     **/

    void readwrite() { keydata_.get_allocator().readwrite(keydata_.data()); }

  private:
    bytes_type keydata_; // the bytes of the key are stored in protected memory
};

} // namespace sodium

template<std::size_t KEYSIZE1, std::size_t KEYSIZE2>
bool
operator==(const sodium::key<KEYSIZE1>& k1, const sodium::key<KEYSIZE2>& k2)
{
    // Don't do this (side channel attack):
    // std::equal(k1.data(), k1.data() + k1.size(),
    //            k2.data());

#ifndef NDEBUG
    std::cerr << "DEBUG: sodium::key::operator==() called" << std::endl;
#endif // ! NDEBUG

    // compare two keys in constant time instead:
    return (k1.size() == k2.size()) &&
           (sodium_memcmp(k1.data(), k2.data(), k1.size()) == 0);
}

template<std::size_t KEYSIZE1, std::size_t KEYSIZE2>
bool
operator!=(const sodium::key<KEYSIZE1>& k1, const sodium::key<KEYSIZE2>& k2)
{
#ifndef NDEBUG
    std::cerr << "DEBUG: sodium::key::operator!=() called" << std::endl;
#endif // ! NDEBUG

    return (!(k1 == k2));
}