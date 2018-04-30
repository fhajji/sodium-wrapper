// key.cpp -- Sodium Key Wrapper, Key(s) with variable length at runtime.
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

#include "keyvar.h"
#include <sodium.h>

using sodium::KeyVar;

bool operator== (const KeyVar &k1, const KeyVar &k2)
{
  // Don't do this (side channel attack):
  // return (k1.size() == k2.size())
  //     &&
  //   std::equal(k1.data(), k1.data() + k1.size(),
  // 	     k2.data());

  // Compare in constant time instead:
  return (k1.size() == k2.size())
	  &&
    (sodium_memcmp(k1.data(), k2.data(), k1.size()) == 0);
}

bool operator!= (const KeyVar &k1, const KeyVar &k2)
{
  return (! (k1 == k2));
}