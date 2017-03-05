// sodiumfilecryptor.h -- file encryption/decryption
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMFILECRYPTOR_H_
#define _SODIUMFILECRYPTOR_H_

#include "sodiumkey.h"
#include "sodiumnonce.h"
#include "sodiumcryptoraead.h"

#include <sodium.h>

namespace Sodium {

class FileCryptor {
 public:

  /**
   * Each block of plaintext will be encrypted to a block of the
   * same size of ciphertext, combined with a MAC of size MACSIZE.
   * Note that the total blocksize of the mac+ciphertext will be
   * MACSIZE + plaintext.size() for each block.
   **/
  constexpr static std::size_t MACSIZE = CryptorAEAD::MACSIZE;

  /**
   * We can compute the hash of the (MAC+)ciphertext of the whole
   * file using a key of so many bytes:
   *   - HASHKEYSIZE is the recommended number of key bytes
   *   - HASHKEYSIZE_MIN is the minimum number of key bytes
   *   - HASHKEYSIZE_MAX is the maximum number of key bytes
   **/
  constexpr static std::size_t HASHKEYSIZE     = crypto_generichash_KEYBYTES;
  constexpr static std::size_t HASHKEYSIZE_MIN = crypto_generichash_KEYBYTES_MIN;
  constexpr static std::size_t HASHKEYSIZE_MAX = crypto_generichash_KEYBYTES_MAX;

  /**
   * The hash can be stored in so many bytes:
   *   - HASHSIZE is the minimum recommended number of bytes
   *   - HASHSIZE_MIN is the minimum number of bytes
   *   - HASHSIZE_MAX is the maximum number of bytes
   **/

  constexpr static std::size_t HASHSIZE     = crypto_generichash_BYTES;
  constexpr static std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
  constexpr static std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;
  
  /**
   * Encrypt/Decrypt a file using a key, an initial nonce, and a
   * fixed blocksize, using the algorithm of Sodium::StreamCryptor:
   *
   * Each block is encrypted individually, using the key and a running
   * nonce initialized with the initial nonce; and an authenticated
   * MAC is appended to the ciphertext to prevent individual tampering
   * of the blocks. The running nonce is incremented after each block,
   * so that swapping of ciphertext blocks is detected.
   *
   * To detect truncating of whole blocks of ciphertext at the end
   * (and to further detect tampering in the midst of the file),
   * generic hashing with a hashing key (preferably HASHSIZE bytes,
   * but no less than HASHSIZE_MIN and no more than HASHSIZE_MAX
   * bytes) is applied to the whole ciphertext+MACs, and that hash is
   * appended to the end of the file.
   *
   * The size of the hash can be selected by the user. It is perferably
   * HASHSIZE bytes, but should be no less than HASHSIZE_MIN and no
   * more than HASHSIZE_MAX bytes. To decrypt the file, the size of
   * the hash MUST be the same as the one given here.
   **/

  FileCryptor(const Key &key,
	      const Nonce<NONCESIZE_AEAD> &nonce,
	      const std::size_t blocksize,
	      const Key &hashkey,
	      const std::size_t hashsize) :
  key_ {key}, nonce_ {nonce}, header_ {}, blocksize_ {blocksize},
  hashkey_ {hashkey}, hashsize_ {hashsize} {
      // some sanity checks, before we start
      if (key.size() != Key::KEYSIZE_AEAD)
	throw std::runtime_error {"Sodium::FileCryptor(): wrong key size"};
      if (blocksize < 1)
	throw std::runtime_error {"Sodium::FileCryptor(): wrong blocksize"};
      if (hashkey.size() < HASHKEYSIZE_MIN)
	throw std::runtime_error {"Sodium::FileCryptor(): hash key too small"};
      if (hashkey.size() > HASHKEYSIZE_MAX)
	throw std::runtime_error {"Sodium::FileCryptor(): hash key too big"};

  }

  void encrypt(std::istream &istr, std::ostream &ostr);
  void decrypt(std::ifstream &ifs, std::ostream &ostr);

 private:
  Key                   key_, hashkey_;
  Nonce<NONCESIZE_AEAD> nonce_;
  data_t                header_;
  std::size_t           blocksize_, hashsize_;
  
  CryptorAEAD           sc_aead_;
};
  
} // namespace Sodium

#endif // _SODIUMFILECRYPTOR_H_
