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
#include <istream>
#include <ostream>

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

  void encrypt(std::istream &istr, std::ostream &ostr);
  void decrypt(std::istream &istr, std::ostream &ostr);
  
 private:
  Key                   key_;
  Nonce<NONCESIZE_AEAD> nonce_;
  data_t                header_;
  std::size_t           blocksize_;
  
  CryptorAEAD           sc_aead_;
};

} // namespace Sodium

#endif // _SODIUMSTREAMCRYPTOR_H_
