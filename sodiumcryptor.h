// sodiumcryptor.h -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCRYPTOR_H_
#define _SODIUMCRYPTOR_H_

#include "sodiumkey.h"
#include "sodiumnonce.h"

#include <vector>
#include <string>

namespace Sodium {

class Cryptor {

 public:
  static constexpr unsigned int NSZ = Sodium::NONCESIZE_SECRETBOX;
  
  // data_t is unprotected memory for bytes of plaintext and ciphertext
  using data_t = std::vector<unsigned char>;
  
  /**
   * Encrypt plaintext using key and nonce, returning ciphertext.
   *
   * Prior to encryption, a MAC of the plaintext is computed with key/nonce
   * and combined with the ciphertext.  This helps detect tampering of
   * the ciphertext and will also prevent decryption.
   *
   * This function will throw a std::runtime_error if the sizes of
   * the key and nonce don't make sense.
   *
   * To safely use this function, it is recommended that
   *   - NO value of nonce is EVER reused again with the same key
   * 
   * Nonces don't need to be kept secret from Eve/Oscar, and therefore
   * don't need to be stored in key_t memory. However, care MUST be
   * taken not to reuse a previously used nonce. When using a big
   * noncespace (24 bits here), generating them randomly e.g. with
   * libsodium's randombytes_buf() may be good enough... but be careful
   * nonetheless.
   *
   * The ciphertext is meant to be sent over the unsecure channel,
   * and it too won't be stored in protected key_t memory.
   **/

  data_t encrypt(const data_t             &plaintext,
		 const Sodium::Key        &key,
		 const Sodium::Nonce<NSZ> &nonce);

  /**
   * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the sizes of
   * the key, nonce and ciphertext don't make sense.
   **/

  data_t decrypt(const data_t             &ciphertext,
		 const Sodium::Key        &key,
		 const Sodium::Nonce<NSZ> &nonce);

  /**
   * Convert the bytes of a ciphertext into a hex string,
   * and return that string.
   **/

  std::string tohex(const data_t &ciphertext);
};

} // namespace Sodium
 
#endif // _SODIUMCRYPTER_H_
