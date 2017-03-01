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
