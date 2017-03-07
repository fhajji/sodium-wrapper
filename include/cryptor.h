// cryptor.h -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _S_CRYPTOR_H_
#define _S_CRYPTOR_H_

#include "common.h"
#include "key.h"
#include "nonce.h"

namespace Sodium {

class Cryptor {

 public:
  static constexpr unsigned int NSZ = Sodium::NONCESIZE_SECRETBOX;
  
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

  data_t encrypt(const data_t     &plaintext,
		 const Key        &key,
		 const Nonce<NSZ> &nonce);

  /**
   * Decrypt ciphertext using key and nonce, returing decrypted plaintext.
   * 
   * If the ciphertext has been tampered with, decryption will fail and
   * this function with throw a std::runtime_error.
   *
   * This function will also throw a std::runtime_error if the sizes of
   * the key, nonce and ciphertext don't make sense.
   **/

  data_t decrypt(const data_t     &ciphertext,
		 const Key        &key,
		 const Nonce<NSZ> &nonce);

};

} // namespace Sodium
 
#endif // _S_CRYPTOR_H_
