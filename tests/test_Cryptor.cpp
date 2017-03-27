// test_Cryptor.cpp -- Test Sodium::Cryptor
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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::Cryptor Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "cryptor.h"
#include "key.h"
#include "nonce.h"
#include <string>

using Sodium::Cryptor;
using Sodium::Key;
using Sodium::Nonce;

using data_t = Sodium::data_t;

bool
test_of_correctness(const std::string &plaintext)
{
  Cryptor sc    {};
  Key     key   (Cryptor::KEYSIZE);
  Nonce<> nonce {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  data_t ciphertext = sc.encrypt(plainblob, key, nonce);
  data_t decrypted  = sc.decrypt(ciphertext, key, nonce);

  key.noaccess();

  BOOST_CHECK(ciphertext.size() == plainblob.size() + Sodium::Cryptor::MACSIZE);
  BOOST_CHECK(decrypted.size()  == plainblob.size());
  
  return plainblob == decrypted;
}

bool
test_of_correctness_detached(const std::string &plaintext)
{
  Cryptor sc    {};
  Key     key   (Cryptor::KEYSIZE);
  Nonce<> nonce {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  data_t mac(Cryptor::MACSIZE);

  data_t ciphertext = sc.encrypt(plainblob, key, nonce, mac);
  data_t decrypted  = sc.decrypt(ciphertext, mac, key, nonce);

  key.noaccess();

  BOOST_CHECK(ciphertext.size() == plainblob.size());
  BOOST_CHECK(decrypted.size()  == plainblob.size());
  
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

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_full_plaintext_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_empty_plaintext_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
