// filecryptor.h -- file encryption/decryption
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

#ifndef _S_FILECRYPTOR_H_
#define _S_FILECRYPTOR_H_

#include "key.h"
#include "nonce.h"
#include "cryptoraead.h"

#include <sodium.h>

namespace Sodium {

class FileCryptor {
 public:

  /**
   * We're encrypting with AEAD.
   **/
  
  constexpr static std::size_t KEYSIZE = Sodium::KEYSIZE_AEAD;
  
  /**
   * Each block of plaintext will be encrypted to a block of the same
   * size of ciphertext, combined with a MAC of size MACSIZE.  Note
   * that the total blocksize of the (MAC || ciphertext) will be
   * MACSIZE + plaintext.size() for each block.
   **/
  constexpr static std::size_t MACSIZE = CryptorAEAD::MACSIZE;

  /**
   * We can compute the hash of the (MAC || ciphertext) of the whole
   * file using a key of so many bytes:
   *   - HASHKEYSIZE is the recommended number of key bytes
   *   - HASHKEYSIZE_MIN is the minimum number of key bytes
   *   - HASHKEYSIZE_MAX is the maximum number of key bytes
   * CAVEAT: for now, only HASHKEYSIZE is allowed.
   **/
  constexpr static std::size_t HASHKEYSIZE     = Sodium::KEYSIZE_HASHKEY;
  constexpr static std::size_t HASHKEYSIZE_MIN = Sodium::KEYSIZE_HASHKEY_MIN;
  constexpr static std::size_t HASHKEYSIZE_MAX = Sodium::KEYSIZE_HASHKEY_MAX;

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
   * bytes) is applied to the whole (MAC || ciphertext)s, and that
   * hash is appended to the end of the file.
   *
   * The size of the hash can be selected by the user. It is perferably
   * HASHSIZE bytes, but should be no less than HASHSIZE_MIN and no
   * more than HASHSIZE_MAX bytes. To decrypt the file, the size of
   * the hash MUST be the same as the one given here.
   **/

  FileCryptor(const Key<KEYSIZE> &key,
	      const Nonce<NONCESIZE_AEAD> &nonce,
	      const std::size_t blocksize,
	      const Key<HASHKEYSIZE> &hashkey,
	      const std::size_t hashsize) :
  key_ {key}, nonce_ {nonce}, header_ {}, blocksize_ {blocksize},
  hashkey_ {hashkey}, hashsize_ {hashsize} {
    // some sanity checks, before we start
    if (blocksize < 1)
      throw std::runtime_error {"Sodium::FileCryptor::FileCryptor(): wrong blocksize"};
    // !!! --->>> hashkey.size() is currently pegged at HASHKEYSIZE <<<--- !!!
    // if (hashkey.size() < HASHKEYSIZE_MIN)
    //   throw std::runtime_error {"Sodium::FileCryptor::FileCryptor(): hash key too small"};
    // if (hashkey.size() > HASHKEYSIZE_MAX)
    //   throw std::runtime_error {"Sodium::FileCryptor::FileCryptor(): hash key too big"};
  }

  /**
   * Encrypt the input stream ISTR in a blockwise fashion, using the
   * algorithm described in Sodium::CryptorAEAD, and write the result
   * in output stream OSTR.
   * 
   * At the same time, compute a generic hash over the resulting
   * ciphertexts and MACs, and when reaching the EOF of ISTR, write
   * that hash at the end of OSTR. The hash is authenticated with the
   * key HASHKEY and will have a size HASHSIZE (bytes).
   **/
  
  void encrypt(std::istream &istr, std::ostream &ostr);

  /**
   * Decrypt the input _file_ stream IFS in a blockwise fashion, using
   * the algorithm described in Sodium::CrytorAEAD, and write the result
   * in output _stream_ OSTR.
   *
   * At the same time, compute a generic authenticated hash of
   * HASHSIZE (bytes) over the input (MAC || ciphertext)s, using the
   * key HASHKEY. Compare that hash with the HASHSIZE bytes stored at
   * the end of IFS.
   *
   * If the the decryption fails for whatever reason:
   *   - the decryption itself fails
   *   - one of the MACs doesn't verify
   *   - the reading or writing fails
   *   - the verification of the authenticated hash fails
   * this function throws a std::runtime_error. It doesn't provide
   * a strong guarantee: some data may already have been written
   * to OSTR prior to throwing.
   *
   * To be able to decrypt a file, a user must provide:
   *   - the key, the initial nonce, the blocksize,
   *   - the authentication key for the hash (with the right number of bytes,
   *     currently pegged at HASHKEYSIZE),
   *   - the hashsize, i.e. the number of bytes of the hash at the end.
   * Failing to provide all those informations, decryption will fail.
   **/
  
  void decrypt(std::ifstream &ifs, std::ostream &ostr);

 private:
  Key<KEYSIZE>          key_;
  Key<HASHKEYSIZE>      hashkey_;
  Nonce<NONCESIZE_AEAD> nonce_;
  data_t                header_;
  std::size_t           blocksize_, hashsize_;
  
  CryptorAEAD           sc_aead_;
};
  
} // namespace Sodium

#endif // _S_FILECRYPTOR_H_
