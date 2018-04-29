// streamverifierpk.cpp -- Public-key signature verifying streaming interface
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

#include "streamverifierpk.h"
#include "common.h"

#include <istream>

using data_t = Sodium::data_t;
using Sodium::StreamVerifierPK;

bool
StreamVerifierPK::verify(std::istream &istr,
			 const data_t &signature)
{
  data_t plaintext(blocksize_, '\0');

  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    // read a whole block of blocksize_ chars (bytes)
    crypto_sign_update(&state_, plaintext.data(), plaintext.size());
  }

  // check to see if we've read a final partial chunk
  std::size_t s = static_cast<std::size_t>(istr.gcount());
  if (s != 0) {
    if (s != plaintext.size())
      plaintext.resize(s);

    crypto_sign_update(&state_, plaintext.data(), plaintext.size());
  }

  // XXX: since crypto_sign_final_verify() doesn't accept a const
  // signature, we need to copy signature beforehand
  data_t signature_copy {signature};
  
  // finalize and compare signatures
  if (crypto_sign_final_verify(&state_,
			       signature_copy.data(),
			       pubkey_.data()) != 0) {
    // message forged
    crypto_sign_init(&state_);
    return false;
  }

  // reset the state for next invocation of sign()
  crypto_sign_init(&state_);
  
  return true;
}
