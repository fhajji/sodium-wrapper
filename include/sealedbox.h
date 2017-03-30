// sealedbox.h -- Sealed boxes / Anonymous senders with Public-key scheme
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

#ifndef _S_SEALEDBOX_H_
#define _S_SEALEDBOX_H_

#include <sodium.h>

#include "common.h"
#include "key.h"
#include "keypair.h"

namespace Sodium {

class SealedBox {

 public:

  static constexpr std::size_t KEYSIZE_PUBKEY  = Sodium::KEYSIZE_PUBKEY;
  static constexpr std::size_t KEYSIZE_PRIVKEY = Sodium::KEYSIZE_PRIVKEY;
  static constexpr std::size_t SEALSIZE        = crypto_box_SEALBYTES;

  /**
   * Encrypt plaintext using recipient's public key pubkey. Return
   * ciphertext combined with a seal.
   *
   * This function allows decryption of the sealed ciphertext without
   * knowledge of the sender (anonymous senders), provided that the
   * recipient has the corresponding private key.
   *
   * The public key of the recipient must be KEYSIZE_PUBKEY  bytes long.
   * 
   * Internally, the sealed ciphertext contains a MAC so that
   * tampering will render decryption impossible.
   *
   * The size of the returned sealed ciphertext is:
   *  SEALSIZE + plaintext.size()
   * bytes.
   * 
   * To thwart Man-in-the-Middle attacks, it is the responsibility of
   * the sender to verify (by other means, like certificates, web
   * of trust, etc.) that the public key of the recipient does indeed
   * belong to the _real_ recipient of the message. This is NOT ensured by
   * this function here.
   **/

  data_t encrypt(const data_t &plaintext,
		 const data_t &pubkey);

  /**
   * Encrypt plaintext using recipient's public key part of
   * keypair. Return ciphertext combined with a seal.
   *
   * Otherwise, see encrypt() above.
   **/

  data_t encrypt(const data_t  &plaintext,
		 const KeyPair &keypair) {
    return encrypt(plaintext, keypair.pubkey());
  }
  
  /**
   * Decrypt the sealed ciphertext with the private key privkey, and
   * the corresponding public key pubkey. Return decrypted text on
   * success.
   * 
   * The decryption can fail for two reasons:
   *   - the ciphertext or the embedded MAC have been tampered with
   *   - the seal didn't match our private/public keypair.
   * In both cases, throw a std::runtime_error.
   * 
   * The seal contains enough information to decrypt the ciphertext,
   * provided a private key is given, but not enough information for
   * the decrypter to recover the identity / privkey of the encrypter.
   *
   * The private key of the recipient must be KEYSIZE_PRIVKEY bytes long.
   * The public  key of the recipient must be KEYSIZE_PUBKEY  bytes long.
   * Both keys must be inter-related, i.e. created either by
   *   - libsodium's crypto_box_[seed_]keypair()
   *   or by
   *   - Sodium::KeyPair
   **/
  
  data_t decrypt(const data_t               &ciphertext_with_seal,
		 const Key<KEYSIZE_PRIVKEY> &privkey,
		 const data_t               &pubkey);

  /**
   * Decrypt the sealed ciphertext with the private key part privkey,
   * and the corresponding public key part pubkey, both from
   * keypair. Return decrypted text on success. Throw std::runtime_error
   * on failure.
   * 
   * Otherwise, see decrypt() above.
   **/
  
  data_t decrypt(const data_t  &ciphertext_with_seal,
		 const KeyPair &keypair) {
    return decrypt(ciphertext_with_seal,
		   keypair.privkey(),
		   keypair.pubkey());
  }
};

} // namespace Sodium
 
#endif // _S_SEALEDBOX_H_
