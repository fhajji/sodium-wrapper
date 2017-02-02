// sodiumtester.h -- Test Harness SodiumTester.
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMTESTER_H_
#define _SODIUMTESTER_H_

#include <string>

class SodiumTester
{  
 public:
  SodiumTester();
  SodiumTester(const SodiumTester &) = delete; // NoCopy
  SodiumTester & operator= (const SodiumTester &) = delete; // NoCopy

  // Here go the test functions for the C++ libsodium wrappers:
  std::string test0(const std::string &plaintext);
};

#endif // _SODIUMTESTER_H_
