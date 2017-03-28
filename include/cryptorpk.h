// cryptorpk.h -- Public-key encryption / decryption with MAC
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

namespace Sodium {

class CryptorPK {

 public:

  static constexpr unsigned int NSZPK               = Sodium::NONCESIZE_PK;
  static constexpr std::size_t  KEYSIZE_PUBKEY      = Key::KEYSIZE_PUBKEY;
  static constexpr std::size_t  KEYSIZE_PRIVKEY     = Key::KEYSIZE_PRIVKEY;
  static constexpr std::size_t  MACSIZE             = crypto_box_MACBYTES;

  /**
   * Encrypt plaintext using recipient's public key, sign it using
   * sender's private key, and a nonce. Compute an authentication tag
   * MAC as well. Return (MAC || ciphertext); i.e. ciphertext prepended
   * by MAC.
   *
   * Any modification of the returned MAC+ciphertext will render
   * decryption impossible.
   * 
   * The nonce is public and can be sent along the MAC+ciphertext. The
   * private key is private and MUST NOT be sent over the channel. The
   * public key is intended to be widely known, even by attackers.
   *
   * To thwart Man-in-the-Middle attacks, it is the responsibility of
   * the recipient to verify (by other means, like certificates, web
   * of trust, etc.) that the public key of the sender does indeed
   * belong to the _real_ sender of the message. This is NOT ensured by
   * this function here.
   *
   * This function can be used repeately with the same key, but you MUST
   * then make sure never to reuse the same nonce. The easiest way to achieve
   * this is to increment nonce after or prior to each encrypt() invocation.
   * 
   * The public  key must be KEYSIZE_PUBKEY  bytes long
   * The private key must be KEYSIZE_PRIVKEY bytes long
   * The nonce       must be NSZPK           bytes long
   * 
   * The MAC+ciphertext size is 
   *    MACSIZE + plaintext.size()
   * bytes long.
   **/

  data_t encrypt(const data_t       &plaintext,
		 const data_t       &pubkey,
		 const Key          &privkey,
		 const Nonce<NSZPK> &nonce);

  /**
   * Encrypt plaintext using recipient's public key, sign it using
   * sender's private key, and a nonce. Compute an authentication tag
   * MAC as well. Return (MAC || ciphertext); i.e. ciphertext prepended
   * by MAC.
   *
   * The public key of the recipient and private key of the sender
   * can be provided as a KeyPair (e.g. for self-signed, self-addressed
   * messages).
   *
   * Otherwise, see encrypt() above.
   **/
  data_t encrypt(const data_t       &plaintext,
		 const KeyPair      &keypair,
		 const Nonce<NSZPK> &nonce);
  
  /**
   * Decrypt ciphertext using recipient's private key and nonce, and
   * verify the signature using the sender's public key, returing
   * decrypted plaintext.
   * 
   * If the ciphertext or the MAC have been tampered with, or if
   * the signature doesn't verify (e.g. because the sender isn't
   * the one who she claims to be), decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the sizes of
   * the keys, nonce and ciphertexts don't make sense.
   **/

  data_t decrypt(const data_t       &ciphertext_with_mac,
		 const Key          &privkey,
		 const data_t       &pubkey,
		 const Nonce<NSZPK> &nonce);

  /**
   * Decrypt ciphertext using recipient's private key and nonce,
   * and verify the signature the signature using the sender's public
   * key, returning decrypted plaintext.
   *
   * The private key of the recipient and the public key of the sender
   * can be provided as a KeyPair (e.g. for self-signed, self-addressed
   * messages).
   *
   * Otherwise, see decrypt() above.
   **/
  
  data_t decrypt(const data_t       &ciphertext_with_mac,
		 const KeyPair      &keypair,
		 const Nonce<NSZPK> &nonce);
};

} // namespace Sodium
 
#endif // _S_CRYPTORPK_H_
