// streamcryptor.cpp -- Symmetric blockwise stream encryption/decryption
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

#include "streamcryptor.h"

using Sodium::StreamCryptor;
using Sodium::CryptorAEAD;

void
StreamCryptor::encrypt(std::istream &istr, std::ostream &ostr)
{
  data_t plaintext(blocksize_, '\0');
  CryptorAEAD::nonce_type running_nonce {nonce_};
  
  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    data_t ciphertext = sc_aead_.encrypt(header_, plaintext,
					 key_, running_nonce);
    running_nonce.increment();

    ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    if (!ostr)
      throw std::runtime_error {"Sodium::StreamCryptor::encrypt() error writing full chunk to stream"};
  }

  // check to see if we've read a final partial chunk
  auto s = istr.gcount();
  if (s != 0) {
    if (s != plaintext.size())
      plaintext.resize(s);

    data_t ciphertext = sc_aead_.encrypt(header_, plaintext,
					 key_, running_nonce);
    // running_nonce.increment() not needed anymore...
    ostr.write(reinterpret_cast<char *>(ciphertext.data()), ciphertext.size());
    if (!ostr)
      throw std::runtime_error {"Sodium::StreamCryptor::encrypt() error writing final chunk to stream"};
  }
}

void
StreamCryptor::decrypt(std::istream &istr, std::ostream &ostr)
{
  data_t ciphertext(MACSIZE + blocksize_, '\0');
  CryptorAEAD::nonce_type running_nonce {nonce_};   // restart with saved nonce_

  while (istr.read(reinterpret_cast<char *>(ciphertext.data()),
		   MACSIZE + blocksize_)) {
    // we've got a whole MACSIZE + blocksize_ chunk
    data_t plaintext = sc_aead_.decrypt(header_, ciphertext,
					key_, running_nonce);
    running_nonce.increment();

    ostr.write(reinterpret_cast<char *>(plaintext.data()), plaintext.size());
    if (!ostr)
      throw std::runtime_error {"Sodium::StreamCryptor::decrypt() error writing full chunk to stream"};
  }

  // check to see if we've read a final partial chunk
  auto s = istr.gcount();
  if (s != 0) {
    // we've got a partial chunk
    if (s != ciphertext.size())
      ciphertext.resize(s);

    data_t plaintext = sc_aead_.decrypt(header_, ciphertext,
					key_, running_nonce);
    // no need to running_nonce.increment() anymore...

    ostr.write(reinterpret_cast<char *>(plaintext.data()), plaintext.size());
    if (!ostr)
      throw std::runtime_error {"Sodium::StreamCryptor::decrypt() error writing final chunk to stream"};
  }
}
