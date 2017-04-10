// keypairsign.cpp -- Sodium KeyPairSign Wrapper
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

#include "keypairsign.h"

using Sodium::KeyPairSign;

bool operator== (const KeyPairSign &kp1, const KeyPairSign &kp2)
{
  // Don't do this (side channel attack):
  //   return (kp1.pubkey() == kp2.pubkey()     // std::vector::operator==()
  // 	  &&
  // 	  kp1.privkey() == kp2.privkey()); // Sodium::Key<KEYSIZE_PRIVKEY>::operator==()

  // Compare pubkeys in constant time instead
  // (privkeys are also compared in constant time
  // using Sodium::Key<KEYSIZE_PRIVKEY>::operator==()):
  return (kp1.pubkey().size() == kp2.pubkey().size()
	  &&
	  (sodium_memcmp(kp1.pubkey().data(), kp2.pubkey().data(),
			 kp1.pubkey().size()) == 0)
	  &&
	  kp1.privkey() == kp2.privkey());
}

bool operator!= (const KeyPairSign &kp1, const KeyPairSign &kp2)
{
  return (! (kp1 == kp2));
}
