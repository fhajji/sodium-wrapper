// sodiumutils.cpp -- Common functions.
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include <sodium.h>
#include <string>
#include "sodiumcommon.h"

std::string
Sodium::tohex (const Sodium::data_t &in)
{
  const std::size_t hexbuf_size = in.size() * 2 + 1;
  std::vector<char> hexbuf(hexbuf_size);
  
  // convert [in.cbegin(), in.cend()) into hex:
  if (! sodium_bin2hex(hexbuf.data(), hexbuf_size,
		       in.data(), in.size()))
    throw std::runtime_error {"Sodium::tohex() overflowed"};

  // In C++17, we could construct a std::string with hexbuf_size chars,
  // and modify it directly through non-const data(). Unfortunately,
  // in C++11 and C++14, std::string's data() is const only, so we need
  // to copy the data over from std::vector<char> to std::string for now.
  
  // return hex output as a string:
  std::string outhex {hexbuf.cbegin(), hexbuf.cend()};
  return outhex;
}
