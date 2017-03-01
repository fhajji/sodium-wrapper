// sodiumstreamcryptor.h -- Symmetric blockwise stream encryption/decryption
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMSTREAMCRYPTOR_H_
#define _SODIUMSTREAMCRYPTOR_H_

#include <sodium.h>

#include "sodiumkey.h"
#include "sodiumnonce.h"
#include "sodiumcryptoraead.h"

#include <stdexcept>
#include <vector>

namespace Sodium {

class StreamCryptor {
 public:
  using data_t  = CryptorAEAD::data_t;

  constexpr static std::size_t MACSIZE = Sodium::CryptorAEAD::MACSIZE;
  
 StreamCryptor(const Key &key,
	       const Nonce<NONCESIZE_AEAD> &nonce,
	       const std::size_t blocksize) :
  key_ {key}, nonce_ {nonce}, header_ {}, blocksize_ {blocksize} {
    // some sanity checks, before we start
    if (key.size() != Key::KEYSIZE_AEAD)
      throw std::runtime_error {"Sodium::SodiumCryptor(): wrong key size"};
    if (blocksize < 1)
      throw std::runtime_error {"Sodium::SodiumCryptor(): wrong blocksize"};
    key_.readonly();
  }

  /**
   * Encrypt a chunk of plaintext, returning a chunk of mac+ciphertext.
   * If (plaintext.size() != blocksize), throw a std::runtime_exception.
   * After encryption, the stored copy of nonce is incremented.
   **/
  
  data_t encrypt(const data_t &plaintext);

  /**
   * Decrypt a chunk of MAC+ciphertext, using the current value
   * (state) of nonce. Upon successuful decryption, return the plaintext
   * and increment the stored nonce, so we're ready to decrypt the next
   * chunk of MAC+ciphertext.
   **/
  
  data_t decrypt(const data_t &ciphtertext_with_macs);
  
 private:
  Key                   key_;
  Nonce<NONCESIZE_AEAD> nonce_;
  data_t                header_;
  std::size_t           blocksize_;
  
  CryptorAEAD           sc_aead_;
};

} // namespace Sodium

#endif // _SODIUMSTREAMCRYPTOR_H_
