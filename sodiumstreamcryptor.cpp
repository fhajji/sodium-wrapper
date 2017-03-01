// sodiumstreamcryptor.cpp -- Symmetric blockwise stream encryption/decryption
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumstreamcryptor.h"

Sodium::StreamCryptor::data_t
Sodium::StreamCryptor::encrypt (const Sodium::StreamCryptor::data_t &plaintext)
{
  // XXX no chunking for now
  data_t ciphertext = sc_aead_.encrypt(header_, plaintext,
				       key_, nonce_);
  nonce_.increment();

  return ciphertext;
}

Sodium::StreamCryptor::data_t
Sodium::StreamCryptor::decrypt (const Sodium::StreamCryptor::data_t &ciphertext_with_macs)
{
  // XXX no chunking for now
  data_t plaintext = sc_aead_.decrypt(header_, ciphertext_with_macs,
				      key_, nonce_);
  nonce_.increment();

  return plaintext;
}

void
Sodium::StreamCryptor::encrypt(std::istream &istr, std::ostream &ostr)
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
Sodium::StreamCryptor::decrypt(std::istream &istr, std::ostream &ostr)
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
