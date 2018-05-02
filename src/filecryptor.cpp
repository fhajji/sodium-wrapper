// filecryptor.cpp -- file encryption/decryption
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

#include "common.h"
#include "filecryptor.h"

#include <ios>
#include <fstream>
#include <sodium.h>

using bytes = sodium::bytes;
using sodium::FileCryptor;
using sodium::cryptor_aead;

void
FileCryptor::encrypt(std::istream &istr, std::ostream &ostr)
{
  // the hash streaming API
  bytes hash(hashsize_, '\0');
  crypto_generichash_state state;
  crypto_generichash_init(&state,
			  hashkey_.data(), hashkey_.size(),
			  hashsize_);

  // the encryption API
  bytes plaintext(blocksize_, '\0');
  cryptor_aead<>::nonce_type running_nonce {nonce_};

  // for each full block...
  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    // encrypt the block (with MAC)
    bytes ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
    running_nonce.increment();

    ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    if (!ostr)
      throw std::runtime_error {"sodium::FileCryptor::encrypt() error writing full chunk to file"};

    // update the hash
    crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
  }

  // check to see if we've read a final partial chunk
  std::size_t s = static_cast<std::size_t>(istr.gcount());
  if (s != 0) {
    if (s != plaintext.size())
      plaintext.resize(s);

    // encrypt the final partial block
    bytes ciphertext = sc_aead_.encrypt(header_, plaintext, running_nonce);
    // running_nonce.increment() not needed anymore...
    ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    if (!ostr)
      throw std::runtime_error {"sodium::FileCryptor::encrypt() error writing final chunk to file"};

    // update the hash with the final partial block
    crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
  }

  // finish computing the hash, and write it to the end of the stream
  crypto_generichash_final(&state, hash.data(), hash.size());
  ostr.write(reinterpret_cast<char *>(hash.data()), hash.size());
  if (!ostr)
    throw std::runtime_error {"sodium::FileCryptor::encrypt() error writing hash to file"};
}

void
FileCryptor::decrypt(std::ifstream &ifs, std::ostream &ostr)
{
  // the hash streaming API
  bytes hash(hashsize_, '\0');
  crypto_generichash_state state;
  crypto_generichash_init(&state,
			  hashkey_.data(), hashkey_.size(),
			  hashsize_);

  // the decryption API
  bytes ciphertext(MACSIZE + blocksize_, '\0');
  cryptor_aead<>::nonce_type running_nonce {nonce_}; // restart with saved nonce_

  // before we start decrypting, fetch the hash block at the end of the file.
  // It should be exactly hashsize_ bytes long.
  bytes hash_saved(hashsize_, '\0');
  ifs.seekg(- static_cast<std::streamoff>(hashsize_), std::ios_base::end);
  if (!ifs)
    throw std::runtime_error {"sodium::FileCryptor::decrypt(): can't seek to the end for hash"};
  std::ifstream::pos_type hash_pos = ifs.tellg(); // where the hash starts

  if (! ifs.read(reinterpret_cast<char *>(hash_saved.data()),
		 hash_saved.size())) {
    // We've got a partial read
    auto s = ifs.gcount();
    if (s != 0 && static_cast<std::size_t>(s) != hashsize_)
      throw std::runtime_error {"sodium::FileCryptor::decrypt(): read partial hash"};
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
    bytes plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
    running_nonce.increment();

    ostr.write(reinterpret_cast<char *>(plaintext.data()), plaintext.size());
    if (!ostr)
      throw std::runtime_error {"sodium::FileCryptor::decrypt() error writing full chunk to file"};

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
      if (! ciphertext.empty()) {
	bytes plaintext = sc_aead_.decrypt(header_, ciphertext, running_nonce);
	// no need to running_nonce.increment() anymore...

	ostr.write(reinterpret_cast<char *>(plaintext.data()),
		   plaintext.size());
	if (!ostr)
	  throw std::runtime_error {"sodium::StreamCryptor::decrypt() error writing final chunk to file"};

	crypto_generichash_update(&state, ciphertext.data(), ciphertext.size());
      }
    }
  }
  
  // finish computing the hash, and save it into the variable 'hash'
  crypto_generichash_final(&state, hash.data(), hash.size());

  // finally, compare both hashes!
  if (hash != hash_saved)
    throw std::runtime_error {"sodium::FileCryptor::decrypt() hash mismatch!"};
}
