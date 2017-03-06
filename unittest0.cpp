// unittest0.cpp -- Test the Sodium::Cryptor
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Compile with:
//   mkdir build
//   cd build
//   cmake ..
//   make
//   cd CMakeFiles/sodiumtester.dir   # this is where the .o files are!
//   c++ -Wall -std=c++11 -I /usr/local/include -c ../../../unittest0.cpp
//   c++ -L /usr/local/lib -o unittest0 unittest0.o sodiumcryptor.cpp.o -lsodium -lboost_unit_test_framework

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::Cryptor Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "sodiumcryptor.h"
#include "sodiumkey.h"
#include "sodiumnonce.h"
#include <string>

using data_t = Sodium::data_t;

bool
test_of_correctness(std::string &plaintext)
{
  Sodium::Cryptor sc {};
  Sodium::Key     key(Sodium::Key::KEYSIZE_SECRETBOX);
  Sodium::Nonce<> nonce {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  data_t ciphertext = sc.encrypt(plainblob, key, nonce);
  data_t decrypted  = sc.decrypt(ciphertext, key, nonce);

  key.noaccess();

  return plainblob == decrypted;
}

BOOST_AUTO_TEST_SUITE ( sodium_test_suite );

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_full_plaintext )
{
  BOOST_REQUIRE(sodium_init() != -1);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_empty_plaintext )
{
  BOOST_REQUIRE(sodium_init() != -1);

  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
