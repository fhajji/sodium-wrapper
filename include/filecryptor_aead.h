// filecryptor_aead.h -- file encryption/decryption with AEAD (ad hoc)
//
// ISC License
// 
// Copyright (C) 2018 Farid Hajji <farid@hajji.name>
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

#pragma once

#include "key.h"
#include "keyvar.h"
#include "nonce.h"
#include "aead.h"

#include <sodium.h>
#include <fstream>

/**
* Deprecated. Use sodium::filecryptor instead.
*
* This is an ad-hoc filecryptor using an AEAD construction.
* It will be replaced by a more robust one using
* sodium::secretstream.
**/

namespace sodium {

template <typename BT=bytes>
class filecryptor_aead {
 public:

  /**
   * We're encrypting with AEAD.
   **/
  
  constexpr static std::size_t KEYSIZE = aead<BT>::KEYSIZE;
  
  /**
   * Each block of plaintext will be encrypted to a block of the same
   * size of ciphertext, combined with a MAC of size MACSIZE.  Note
   * that the total blocksize of the (MAC || ciphertext) will be
   * MACSIZE + plaintext.size() for each block.
   **/
  constexpr static std::size_t MACSIZE = aead<BT>::MACSIZE;

  /**
   * We can compute the hash of the (MAC || ciphertext) of the whole
   * file using a key of so many bytes:
   *   - HASHKEYSIZE is the recommended number of key bytes
   *   - HASHKEYSIZE_MIN is the minimum number of key bytes
   *   - HASHKEYSIZE_MAX is the maximum number of key bytes
   **/
  constexpr static std::size_t HASHKEYSIZE     = sodium::KEYSIZE_HASHKEY;
  constexpr static std::size_t HASHKEYSIZE_MIN = sodium::KEYSIZE_HASHKEY_MIN;
  constexpr static std::size_t HASHKEYSIZE_MAX = sodium::KEYSIZE_HASHKEY_MAX;

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
   * fixed blocksize, using the algorithm of sodium::streamcryptor_aead:
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

  filecryptor_aead(const typename aead<BT>::key_type &key,
	      const typename aead<BT>::nonce_type &nonce,
	      const std::size_t                 blocksize,
	      const keyvar<>                   &hashkey,
	      const std::size_t                 hashsize) :
  sc_aead_{ aead<BT>(key) }, hashkey_{ hashkey },
  nonce_{ nonce }, header_{},
  blocksize_ {blocksize}, hashsize_ {hashsize} {
    // some sanity checks, before we start
    if (blocksize < 1)
      throw std::runtime_error {"sodium::filecryptor_aead::filecryptor_aead(): wrong blocksize"};
    if (hashkey.size() < HASHKEYSIZE_MIN)
      throw std::runtime_error {"sodium::filecryptor_aead::filecryptor_aead(): hash key too small"};
    if (hashkey.size() > HASHKEYSIZE_MAX)
      throw std::runtime_error {"sodium::filecryptor_aead::filecryptor_aead(): hash key too big"};
  }

  /**
   * Encrypt the input stream ISTR in a blockwise fashion, using the
   * algorithm described in sodium::aead, and write the result
   * in output stream OSTR.
   * 
   * At the same time, compute a generic hash over the resulting
   * ciphertexts and MACs, and when reaching the EOF of ISTR, write
   * that hash at the end of OSTR. The hash is authenticated with the
   * key HASHKEY and will have a size HASHSIZE (bytes).
   **/
  
  void encrypt(std::istream &istr, std::ostream &ostr)
  {
	  // the hash streaming API
	  BT hash(hashsize_, '\0');
	  crypto_generichash_state state;
	  crypto_generichash_init(&state,
		  hashkey_.data(), hashkey_.size(),
		  hashsize_);

	  // the encryption API
	  BT plaintext(blocksize_, '\0');
	  typename aead<BT>::nonce_type running_nonce{ nonce_ };

	  // for each full block...
	  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
		  // encrypt the block (with MAC)
		  BT ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
		  running_nonce.increment();

		  ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
		  if (!ostr)
			  throw std::runtime_error{ "sodium::filecryptor_aead::encrypt() error writing full chunk to file" };

		  // update the hash
		  crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
	  }

	  // check to see if we've read a final partial chunk
	  std::size_t s = static_cast<std::size_t>(istr.gcount());
	  if (s != 0) {
		  if (s != plaintext.size())
			  plaintext.resize(s);

		  // encrypt the final partial block
		  BT ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
		  // running_nonce.increment() not needed anymore...
		  ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
		  if (!ostr)
			  throw std::runtime_error{ "sodium::filecryptor_aead::encrypt() error writing final chunk to file" };

		  // update the hash with the final partial block
		  crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
	  }

	  // finish computing the hash, and write it to the end of the stream
	  crypto_generichash_final(&state, hash.data(), hash.size());
	  ostr.write(reinterpret_cast<char *>(hash.data()), hash.size());
	  if (!ostr)
		  throw std::runtime_error{ "sodium::filecryptor_aead::encrypt() error writing hash to file" };
  }

  /**
   * Decrypt the input _file_ stream IFS in a blockwise fashion, using
   * the algorithm described in sodium::aead, and write the result
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
  
  void decrypt(std::ifstream &ifs, std::ostream &ostr)
  {
	  // the hash streaming API
	  BT hash(hashsize_, '\0');
	  crypto_generichash_state state;
	  crypto_generichash_init(&state,
		  hashkey_.data(), hashkey_.size(),
		  hashsize_);

	  // the decryption API
	  BT ciphertext(MACSIZE + blocksize_, '\0');
	  typename aead<BT>::nonce_type running_nonce{ nonce_ }; // restart with saved nonce_

	  // before we start decrypting, fetch the hash block at the end of the file.
	  // It should be exactly hashsize_ bytes long.

	  BT hash_saved(hashsize_, '\0');
	  ifs.seekg(-static_cast<std::streamoff>(hashsize_), std::ios_base::end);
	  if (!ifs)
		  throw std::runtime_error{ "sodium::filecryptor_aead::decrypt(): can't seek to the end for hash" };
	  std::ifstream::pos_type hash_pos = ifs.tellg(); // where the hash starts

	  if (!ifs.read(reinterpret_cast<char *>(hash_saved.data()),
		  hash_saved.size())) {
		  // We've got a partial read
		  auto s = ifs.gcount();
		  if (s != 0 && static_cast<std::size_t>(s) != hashsize_)
			  throw std::runtime_error{ "sodium::filecryptor_aead::decrypt(): read partial hash" };
	  }

	  // Let's go back to the beginning of the file, and start reading
	  // and decrypting...
	  ifs.seekg(0, std::ios_base::beg);
	  std::ifstream::pos_type current_pos = ifs.tellg();
	  bool in_hash = false;

	  while (ifs.read(reinterpret_cast<char *>(ciphertext.data()),
		  MACSIZE + blocksize_)
		  && !in_hash) {

		  // before we decrypt, we must be sure that we didn't read
		  // info the hash at the end of the file. drop what we read
		  // in excess
		  current_pos = ifs.tellg();

		  if (current_pos > hash_pos) {
			  ciphertext.resize(ciphertext.size() - static_cast<std::size_t>(current_pos - hash_pos));
			  in_hash = true;
		  }
		  // we've got a whole MACSIZE + blocksize_ chunk
		  BT plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
		  running_nonce.increment();

		  ostr.write(reinterpret_cast<char *>(plaintext.data()), plaintext.size());
		  if (!ostr)
			  throw std::runtime_error{ "sodium::filecryptor_aead::decrypt() error writing full chunk to file" };

		  crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
	  }

	  if (!in_hash) {
		  // check to see if we've read a final partial chunk
		  std::size_t s = static_cast<std::size_t>(ifs.gcount());
		  if (s != 0) {
			  // we've got a partial chunk
			  if (s != ciphertext.size())
				  ciphertext.resize(s);

			  // before we decrypt, we must again be sure that we didn't read
			  // into the hash at the end of the file. drop what we read
			  // in excess
			  current_pos = ifs.tellg();

			  if (current_pos > hash_pos)
				  ciphertext.resize(ciphertext.size() - static_cast<std::size_t>(current_pos - hash_pos));
			  else if (current_pos == std::ifstream::pos_type(-1)) {
				  // we've reached end of file...
				  if (ciphertext.size() > hashsize_)
					  // remove hash, there is still some ciphertext...
					  ciphertext.resize(ciphertext.size() - hashsize_);
				  else
					  // the is no ciphertext remaining, only hash or part of a hash...
					  ciphertext.clear();
			  }

			  // now, attempt to decrypt, if there's still something to decrypt
			  if (!ciphertext.empty()) {
				  BT plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
				  // no need to running_nonce.increment() anymore...

				  ostr.write(reinterpret_cast<char *>(plaintext.data()),
					  plaintext.size());
				  if (!ostr)
					  throw std::runtime_error{ "sodium::filecryptor_aead::decrypt() error writing final chunk to file" };

				  crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
			  }
		  }
	  }

	  // finish computing the hash, and save it into the variable 'hash'
	  crypto_generichash_final(&state, hash.data(), hash.size());

	  // finally, compare both hashes!
	  if (hash != hash_saved)
		  throw std::runtime_error{ "sodium::filecryptor_aead::decrypt() hash mismatch!" };
  }

 private:
  aead<BT>                      sc_aead_;
  keyvar<>                      hashkey_;
  typename aead<BT>::nonce_type nonce_;
  BT                            header_;
  std::size_t                   blocksize_, hashsize_;
};

} // namespace sodium
