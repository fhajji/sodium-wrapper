// sodiumcrypteraead.h -- Symmetric encryption / decryption with MAC and AEAD
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMCRYPTERAEAD_H_
#define _SODIUMCRYPTERAEAD_H_

#include "sodiumkey.h"
#include "sodiumnonce.h"

#include <vector>
#include <string>

namespace Sodium {

class CrypterAEAD
{
 public:
  static constexpr unsigned int NSZA = Sodium::NONCESIZE_AEAD;
  static constexpr std::size_t  MACSIZE = crypto_aead_chacha20poly1305_ABYTES;
  
  // data_t is unprotected memory for bytes of plaintext (header and body)
  // and ciphertext.
  using data_t    = std::vector<unsigned char>;

  // Encrypt plaintext using key and nonce.
  // Additionally, compute an authenticated MAC from header and ciphertext.
  // Return combined (mac tag + ciphertext).
  //
  // Don't forget to increment the nonce after each encryption, when
  // reusing the same key. This is not done automatically here.
  data_t encrypt(const data_t              &header,
		 const data_t              &plaintext,
		 const Sodium::Key         &key,
		 const Sodium::Nonce<NSZA> &nonce);

  // Decrypt ciphertext using key and nonce, returning decrypted text.
  // Additionally, verify integrity of mac tag contained within
  // ciphertext_with_mac, by checking against ciphertext AND header.
  // Throw std::runtime_error if ciphertext or header (or mac) were corrupted.
  data_t decrypt(const data_t              &header,
		 const data_t              &ciphertext_with_mac,
		 const Sodium::Key         &key,
		 const Sodium::Nonce<NSZA> &nonce);

  // Convert ciphertext bytes into a string of hexadecimal symbols.
  std::string tohex(const data_t &ciphertext);
};

} // namespace Sodium

#endif // _SODIUMCRYPTERAEAD_H_
