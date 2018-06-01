// signorpk.cpp -- Public-key signatures / verification
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

#include "signorpk.h"
#include "key.h"
#include "keypairsign.h"
#include "common.h"

#include <stdexcept>
#include <sodium.h>

using bytes = sodium::bytes;
using sodium::SignorPK;
using sodium::keypairsign;

bytes
SignorPK::sign (const bytes       &plaintext,
		const privkey_type &privkey)
{
  bytes plaintext_signed(SIGNATURE_SIZE + plaintext.size());
  if (crypto_sign(plaintext_signed.data(), NULL,
		  plaintext.data(), plaintext.size(),
		  privkey.data()) == -1)
    throw std::runtime_error {"sodium::SignorPK::sign(): crypto_sign() -1"};
  
  return plaintext_signed; // per move semantics
}

bytes
SignorPK::sign_detached (const bytes       &plaintext,
			 const privkey_type &privkey)
{
  bytes signature(SIGNATURE_SIZE);
  unsigned long long signature_size;
  
  if (crypto_sign_detached(signature.data(), &signature_size,
			   plaintext.data(), plaintext.size(),
			   privkey.data()) == -1)
    throw std::runtime_error {"sodium::SignorPK::sign_detached(): crypto_sign_detached() -1"};
  
  // sanity check
  if (signature_size != SIGNATURE_SIZE)
    throw std::runtime_error {"sodium::SignorPK::sign_detached(): wrong signature size"};
  
  return signature; // per move semantics
}

bytes
SignorPK::verify (const bytes &plaintext_with_signature,
		  const bytes &pubkey)
{
  // some sanity checks before we get started
  if (pubkey.size() != KEYSIZE_PUBKEY)
    throw std::runtime_error {"sodium::SignorPK::verify(): wrong pubkey size"};
  if (plaintext_with_signature.size() < SIGNATURE_SIZE)
    throw std::runtime_error {"sodium::SignorPK::verify(): plaintext_with_signature too small for signature"};

  // make space for plaintext without signature
  bytes plaintext(plaintext_with_signature.size() - SIGNATURE_SIZE);
  unsigned long long plaintext_size;

  // let's verify signature now!
  if (crypto_sign_open(plaintext.data(), &plaintext_size,
		       plaintext_with_signature.data(),
		       plaintext_with_signature.size(),
		       pubkey.data()) == -1) {
    throw std::runtime_error {"sodium::SignorPK::verify(): signature didn't verify"};
  }
  
  // yet another sanity check
  if (plaintext_size != plaintext_with_signature.size() - SIGNATURE_SIZE)
    throw std::runtime_error {"sodium::SignorPK::verify(): wrong plaintext size"};
  
  return plaintext; // per move semantics
}

bool
SignorPK::verify_detached (const bytes &plaintext,
			   const bytes &signature,
			   const bytes &pubkey)
{
  // some sanity checks before we get started
  if (pubkey.size() != KEYSIZE_PUBKEY)
    throw std::runtime_error {"sodium::SignorPK::verify_detached(): wrong pubkey size"};
  if (signature.size() != SIGNATURE_SIZE)
    throw std::runtime_error {"sodium::SignorPK::verify_detached(): wrong signature size"};

  // let's verify the detached signature now!
  return crypto_sign_verify_detached(signature.data(),
				     plaintext.data(), plaintext.size(),
				     pubkey.data()) != -1;
}