// streamcryptor.cpp -- Symmetric blockwise stream encryption/decryption
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

#include "streamcryptor.h"

using Sodium::StreamCryptor;

void
StreamCryptor::encrypt(std::istream &istr, std::ostream &ostr)
{
  data_t plaintext(blocksize_, '\0');
  Nonce<NONCESIZE_AEAD> running_nonce {nonce_};
  
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
  Nonce<NONCESIZE_AEAD> running_nonce {nonce_};   // restart with saved nonce_

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
