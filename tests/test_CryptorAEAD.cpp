// test_CryptorAEAD.cpp -- Test Sodium::CryptorAEAD
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::CryptorAEAD Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "cryptoraead.h"
#include "key.h"
#include "nonce.h"
#include <string>

using data_t = Sodium::data_t;

bool
test_of_correctness(const std::string &header,
		    const std::string &plaintext,
		    std::size_t &ciphertext_size,
		    bool falsify_header = false,
		    bool falsify_ciphertext = false)
{
  Sodium::CryptorAEAD                   sc {};
  Sodium::Key                           key(Sodium::Key::KEYSIZE_AEAD);
  Sodium::Nonce<Sodium::NONCESIZE_AEAD> nonce {};

  data_t plainblob    {plaintext.cbegin(), plaintext.cend()};
  data_t headerblob   {header.cbegin(), header.cend()};

  data_t ciphertext = sc.encrypt(headerblob, plainblob, key, nonce);

  if (falsify_ciphertext && ciphertext.size() != 0)
    ++ciphertext[0];

  ciphertext_size = ciphertext.size();
  
  data_t decrypted;

  // falsify the header AFTER encryption!
  if (falsify_header && headerblob.size() != 0)
    ++headerblob[0];
  
  try {
    decrypted  = sc.decrypt(headerblob, ciphertext, key, nonce);
  }
  catch (std::exception &e) {
    return false; // decryption failed;
  }

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
 * ------ FIXME: THIS ADVICE DUMPS CORE !!! ---------------------------
 * If you prefer to to this fixture only once for the whole test
 * suite, replace BOOST_FIXTURE_TEST_SUITE (...) by call call to
 * BOOST_AUTO_TEST_SUITE (sodium_test_suite,
 *                        * boost::unit_test::fixture<SodiumFixture>())
 * i.e. using decorators.
 * ------ FIXME: THIS ADVICE DUMPS CORE !!! ---------------------------
 * 
 * To see the output of the messages, invoke with --log_level=message.
 **/

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_full_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_full_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_empty_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_empty_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_empty_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_full_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_falsify_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, false, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_falsify_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, false, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_falsify_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptorAEAD_test_big_header )
{
  std::string header(Sodium::CryptorAEAD::MACSIZE * 200, 'A');
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  // The following test shows that the header is NOT included in
  // the ciphertext. Only the plaintext and the MAC are included
  // in the ciphertext, no matter how big the header may be.
  // It is the responsability of the user to transmit the header
  // separately from the ciphertext, i.e. to tag it along.
  
  BOOST_CHECK_EQUAL(header.size(), Sodium::CryptorAEAD::MACSIZE * 200);
  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + Sodium::CryptorAEAD::MACSIZE);

  // However, a modification of the header WILL be detected.
  // We modify only the 0-th byte right now, but a modification
  // SHOULD also be detected past MACSIZE bytes... (not tested)
  
  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
}

BOOST_AUTO_TEST_SUITE_END ();
