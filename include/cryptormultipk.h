// cryptormultipk.h -- PK enc/dec with MAC, with precalculated shared key
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

#ifndef _S_CRYPTORPK_H_
#define _S_CRYPTORPK_H_

#include "common.h"
#include "key.h"
#include "keypair.h"
#include "nonce.h"

#include <stdexcept>

#include <sodium.h>

namespace Sodium {

class CryptorMultiPK {

 public:

  static constexpr unsigned int NSZPK               = Sodium::NONCESIZE_PK;
  static constexpr std::size_t  KEYSIZE_PUBKEY      = Key::KEYSIZE_PUBKEY;
  static constexpr std::size_t  KEYSIZE_PRIVKEY     = Key::KEYSIZE_PRIVKEY;
  static constexpr std::size_t  KEYSIZE_SHAREDKEY   = Key::KEYSIZE_SHAREDKEY;
  static constexpr std::size_t  MACSIZE             = crypto_box_MACBYTES;

  /**
   * Create and store an internal shared key built out of a
   * private key and a public key.
   *
   * The private and the public key need not be related, i.e. they
   * need not belong to the same KeyPair and need not necessarily
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
   * privkey, the private key, must be KEYSIZE_PRIVKEY bytes long.
   * pubkey , the public key,  must be KEYSIZE_PUBKEY  bytes long.
   *
   * If the sizes of the keys aren't correct, the constructor
   * will throw a std::runtime_error.
   **/
  
  CryptorMultiPK(const Key    &privkey,
		 const data_t &pubkey)
    : shared_key_(KEYSIZE_SHAREDKEY, false), shared_key_ready_(false)
  {
    set_shared_key(privkey, pubkey);
  }

  CryptorMultiPK(const KeyPair &keypair)
    : shared_key_(KEYSIZE_SHAREDKEY, false), shared_key_ready_(false)
  {
    set_shared_key(keypair.privkey(), keypair.pubkey());
  }
  
  /**
   * Change the shared key by setting it so that it is built out of
   * the public key pubkey, and the private key privkey.
   *
   * privkey must be KEYSIZE_PRIVKEY bytes long. 
   * pubkey  must be KEYSIZE_PUBKEY  bytes long.
   *
   * If the sizes of the keys aren't correct, this function will throw
   * a std::runtime_error and the old shared key (if any) will remain
   * unchanged.
   *
   * If the underlying libsodium function crypto_box_beforenm()
   * returns -1, we throw a std::runtime_error as well, and the state
   * of the shared key is undefined. 
   **/
  
  void set_shared_key(const Key    &privkey,
		      const data_t &pubkey);

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
   * Any modification of the returned MAC+ciphertext will render
   * decryption impossible.
   *
   * The nonce is public and can be sent along the MAC+ciphertext. The
   * private key / shared key are private and MUST NOT be sent over
   * the channel. The public key is intended to be widely known, even
   * by attackers.
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
   * The nonce       must be NSZPK           bytes long
   * 
   * The MAC+ciphertext size is 
   *    MACSIZE + plaintext.size()
   * bytes long.
   *
   * encrypt() will throw a std::runtime_error if
   *  - the size of the nonce is wrong
   *  - the shared key is not ready
   **/

  data_t encrypt(const data_t       &plaintext,
		 const Nonce<NSZPK> &nonce);
  
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
   *  - the size of the nonce is not NSZPK
   *  - the size of the ciphertext_with_mac is not at least MACSIZE
   *  - decryption failed (e.g. because the shared key doesn't match)
   *  - the shared key isn't ready
   **/

  data_t decrypt(const data_t       &ciphertext_with_mac,
		 const Nonce<NSZPK> &nonce);

 private:
  Key  shared_key_;
  bool shared_key_ready_;
};

} // namespace Sodium
 
#endif // _S_CRYPTORPK_H_
