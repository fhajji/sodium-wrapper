// streamsignorpk.cpp -- Public-key signing streaming interface
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

#include "streamsignorpk.h"
#include "common.h"

#include <istream>

using Sodium::data_t;
using Sodium::StreamSignorPK;

data_t
StreamSignorPK::sign(std::istream &istr)
{
  data_t plaintext(blocksize_, '\0');

  while (istr.read(reinterpret_cast<char *>(plaintext.data()), blocksize_)) {
    // read a whole block of blocksize_ chars (bytes)
    crypto_sign_update(&state_, plaintext.data(), plaintext.size());
  }

  // check to see if we've read a final partial chunk
  auto s = istr.gcount();
  if (s != 0) {
    if (static_cast<std::size_t>(s) != plaintext.size())
      plaintext.resize(s);

    crypto_sign_update(&state_, plaintext.data(), plaintext.size());
  }

  // finalize the signature
  data_t signature(SIGNATURE_SIZE);
  crypto_sign_final_create(&state_, signature.data(), NULL, privkey_.data());

  // reset the state for next invocation of sign()
  crypto_sign_init(&state_);
  
  return signature; // using move semantics
}
