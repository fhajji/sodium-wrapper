// test_Cryptor.cpp -- Test Sodium::Cryptor
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

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

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

/**
 * The previous fixture is RAII called _for each_ test case
 * individually; i.e. sodium_init() is initialized multiple times.
 *
 * If you prefer to to this fixture only once for the whole test
 * suite, replace BOOST_FIXTURE_TEST_SUITE (...) by call call to
 * BOOST_AUTO_TEST_SUITE (sodium_test_suite,
 *                        * boost::unit_test::fixture<SodiumFixture>())
 * i.e. using decorators. 
 * 
 * To see the output of the messages, invoke with --log_level=message.
 **/

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
