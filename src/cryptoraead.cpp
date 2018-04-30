// cryptoraead.cpp -- Authenticated Encryption with Added Data
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

#include "cryptoraead.h"

#include <stdexcept>

using bytes = sodium::bytes;
using sodium::CryptorAEAD;

bytes
CryptorAEAD::encrypt (const bytes &header,
		      const bytes      &plaintext,
		      const key_type   &key,
		      const nonce_type &nonce)
{
  // make space for MAC and encrypted message, i.e. (MAC || encrypted)
  bytes ciphertext(MACSIZE + plaintext.size());

  // so many bytes will really be written into output buffer
  unsigned long long clen;
  
  // let's encrypt now!
  crypto_aead_chacha20poly1305_encrypt (ciphertext.data(), &clen,
					plaintext.data(), plaintext.size(),
					(header.empty() ? nullptr : header.data()), header.size(),
					NULL /* nsec */,
					nonce.data(),
					key.data());
  ciphertext.resize(static_cast<std::size_t>(clen));

  return ciphertext;
}

bytes
CryptorAEAD::decrypt (const bytes &header,
		      const bytes         &ciphertext_with_mac,
		      const key_type   &key,
		      const nonce_type &nonce)
{
  // some sanity checks before we get started
  if (ciphertext_with_mac.size() < MACSIZE)
    throw std::runtime_error {"sodium::CryptorAEAD::decrypt() ciphertext length too small for a tag"};

  // make space for decrypted buffer
  bytes plaintext(ciphertext_with_mac.size() - MACSIZE);

  // how many bytes we decrypt
  unsigned long long mlen;
  
  // and now decrypt!
  if (crypto_aead_chacha20poly1305_decrypt (plaintext.data(), &mlen,
					    nullptr /* nsec */,
					    ciphertext_with_mac.data(), ciphertext_with_mac.size(),
					    (header.empty() ? nullptr : header.data()), header.size(),
					    nonce.data(),
					    key.data()) == -1)
    throw std::runtime_error {"sodium::CryptorAEAD::decrypt() can't decrypt or message/tag corrupt"};
  plaintext.resize(static_cast<std::size_t>(mlen));

  return plaintext;
}