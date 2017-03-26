// signorpk.h -- Public-key signatures / verification
//
// ISC License
// 
// Copyright (c) 2017 Farid Hajji <farid@hajji.name>
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

#ifndef _S_SIGNORPK_H_
#define _S_SIGNORPK_H_

#include <stdexcept>

#include <sodium.h>

#include "common.h"
#include "key.h"
#include "keypairsign.h"

namespace Sodium {

class SignorPK {

  /**
   * The Sodium::SignorPK class provides sign() and verify() functions
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
   * pair of public/private _signing_ Keys. Because signing keys
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

  static constexpr std::size_t  KEYSIZE_PUBKEY      = Key::KEYSIZE_PUBKEY_SIGN;
  static constexpr std::size_t  KEYSIZE_PRIVKEY     = Key::KEYSIZE_PRIVKEY_SIGN;
  static constexpr std::size_t  SIGNATURE_SIZE      = crypto_sign_BYTES;

  /**
   * Sign the plaintext with the private key privkey.  Return
   * (signature || plaintext), where signature is SIGNATURE_SIZE bytes
   * long.
   **/

  data_t sign(const data_t       &plaintext,
	      const Key          &privkey);

  /**
   * Sign the plaintext with the private key part of the keypair.
   * Return (signature || plaintext), where signature is
   * SIGNATURE_SIZE bytes long.
   **/
  data_t sign(const data_t       &plaintext,
	      const KeyPairSign  &keypair) {
    return sign(plaintext, keypair.privkey());
  }

  /**
   * Sign the plaintext with the private key privkey. Return the
   * signature, which is SIGNATURE_SIZE bytes long.
   **/
  data_t sign_detached(const data_t &plaintext,
		       const Key    &privkey);
  
  /**
   * Sign the plaintext with the private key part of the keypair.
   * Return the signature, which is SIGNATURE_SIZE bytes long.
   **/
  data_t sign_detached(const data_t       &plaintext,
		       const KeyPairSign  &keypair) {
    return sign_detached(plaintext, keypair.privkey());
  }

  /**
   * Verify the signature contained in plaintext_with_signature
   * against the public key pubkey. On success, return the plaintext
   * without the signature. On failure, throw std::runtime_error.
   *
   * plaintext_with_signature must be (signature || plaintext),
   * with signature being SIGNATURE_SIZE bytes long.
   **/

  data_t verify(const data_t      &plaintext_with_signature,
		const data_t      &pubkey);

  /**
   * Verify the signature contained in plaintext_with_signature
   * against the public key part of the keypair. On success, return
   * the plaintext without the signature. On failure, throw a
   * std::runtime_error.
   * 
   * plaintext_with_signature must be (signature || plaintext),
   * with signature being SIGNATURE_SIZE bytes long.
   **/
  
  data_t verify(const data_t      &plaintext_with_signature,
		const KeyPairSign &keypair) {
    return verify(plaintext_with_signature, keypair.pubkey());
  }

  
  /**
   * Verify the signature of the plaintext against the pubkey.  On
   * success, return true. On failure, return false.  If size of
   * signature isn't SIGNATURE_SIZE bytes, throw std::runtime_error.
   **/
  
  bool verify_detached(const data_t      &plaintext,
		       const data_t      &signature,
		       const data_t      &pubkey);

  /**
   * Verify the signature of the plaintext against the public key part
   * of the keypair. On success, return true. On failure, return
   * false.  If size of signature isn't SIGNATURE_SIZE bytes, throw
   * std::runtime_error.
   **/
  bool verify_detached(const data_t      &plaintext,
		       const data_t      &signature,
		       const KeyPairSign &keypair) {
    return verify_detached(plaintext, signature, keypair.pubkey());
  }

  // TODO: multipart messages (signormultipk.h ?)
};

} // namespace Sodium
 
#endif // _S_SIGNORPK_H_
