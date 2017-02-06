// sodiumcrypter.h -- Symmetric encryption / decryption with MAC
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCRYPTER_H_
#define _SODIUMCRYPTER_H_

#include "sodiumkey.h"
#include "sodiumnonce.h"

#include <vector>
#include <string>

namespace Sodium {

class Crypter
{
 public:
  static constexpr unsigned int NSZ = Sodium::NONCESIZE_SECRETBOX;

  // data_t is unprotected memory for bytes of plaintext, ciphertext and nonces
  using data_t = std::vector<unsigned char>;
  
  // Encrypt plaintext with MAC using key and nonce, returning ciphertext.
  data_t encrypt(const data_t             &plaintext,
		 const Sodium::Key        &key,
		 const Sodium::Nonce<NSZ> &nonce);

  // Decrypt ciphertext using key and nonce, returning decrypted text
  // or throwing std::runtime_error if ciphertext was corrupted.
  data_t decrypt(const data_t             &ciphertext,
		 const Sodium::Key        &key,
		 const Sodium::Nonce<NSZ> &nonce);

  // Convert ciphertext bytes into a string of hexadecimal symbols.
  std::string tohex(const data_t &ciphertext);
};

} // namespace Sodium
 
#endif // _SODIUMCRYPTER_H_
