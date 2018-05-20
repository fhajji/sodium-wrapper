// test_cryptor_aead.cpp -- Test sodium:cryptor_aead
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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::cryptor_aead Test
#include <boost/test/included/unit_test.hpp>

#include "cryptor_aead.h"
#include <string>
#include <sodium.h>

using sodium::cryptor_aead;
using bytes = sodium::bytes;

bool
test_of_correctness(const std::string &header,
		    const std::string &plaintext,
		    std::size_t &ciphertext_size,
		    bool falsify_header = false,
		    bool falsify_ciphertext = false)
{
  cryptor_aead<> sc;                // with random key
  cryptor_aead<>::nonce_type nonce; // random nonce

  bytes plainblob    {plaintext.cbegin(), plaintext.cend()};
  bytes headerblob   {header.cbegin(), header.cend()};

  bytes ciphertext = sc.encrypt(headerblob, plainblob, nonce);

  if (falsify_ciphertext && ciphertext.size() != 0)
    ++ciphertext[0];

  ciphertext_size = ciphertext.size();
  
  bytes decrypted;

  // falsify the header AFTER encryption!
  if (falsify_header && headerblob.size() != 0)
    ++headerblob[0];
  
  try {
    decrypted = sc.decrypt(headerblob, ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    return false; // decryption failed;
  }

  return plainblob == decrypted;
}

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_full_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_full_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_empty_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_empty_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_empty_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_full_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_falsify_plaintext_empty_header )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, false, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_falsify_plaintext_full_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, false, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_falsify_plaintext_falsify_header )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, true));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_aead_test_big_header )
{
  std::string header(cryptor_aead<>::MACSIZE * 200, 'A');
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  // The following test shows that the header is NOT included in
  // the ciphertext. Only the plaintext and the MAC are included
  // in the ciphertext, no matter how big the header may be.
  // It is the responsability of the user to transmit the header
  // separately from the ciphertext, i.e. to tag it along.
  
  BOOST_CHECK_EQUAL(header.size(), cryptor_aead<>::MACSIZE * 200);
  BOOST_CHECK(test_of_correctness(header, plaintext, csize, false, false));
  BOOST_CHECK_EQUAL(csize, plaintext.size() + cryptor_aead<>::MACSIZE);

  // However, a modification of the header WILL be detected.
  // We modify only the 0-th byte right now, but a modification
  // SHOULD also be detected past MACSIZE bytes... (not tested)
  
  BOOST_CHECK(! test_of_correctness(header, plaintext, csize, true, false));
}

BOOST_AUTO_TEST_SUITE_END ()
