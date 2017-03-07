// sodiumtester.h -- Test Harness SodiumTester.
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMTESTER_H_
#define _SODIUMTESTER_H_

#include <string>
#include "common.h"

class SodiumTester
{  
 public:
  using data_t = Sodium::data_t; // shorthand notation...

  SodiumTester();
  SodiumTester(const SodiumTester &) = delete; // NoCopy
  SodiumTester & operator= (const SodiumTester &) = delete; // NoCopy

  // Here go the test functions for the C++ libsodium wrappers:
  std::string test0(const std::string &plaintext);
  bool        test1(const std::string &plaintext);
  bool        test2(const std::string &plaintext,
		    const std::string &pw1, const std::string &pw2);
  std::string test3();
  std::string test4(const std::string &plaintext,
		    const std::string &header);
  bool        test5(const std::string &filename);
  bool        test6(const std::string &filename);
};

#endif // _SODIUMTESTER_H_
