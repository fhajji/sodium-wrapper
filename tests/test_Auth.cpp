// test_Auth.cpp -- Test Sodium::Auth
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::Auth Test
#include <boost/test/included/unit_test.hpp>

#include "auth.h"
#include "key.h"
#include "common.h"

#include <string>

using Sodium::Auth;
using Sodium::Key;
using data_t = Sodium::data_t;

static constexpr std::size_t macsize = Auth::MACSIZE;

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

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_size )
{
  Auth sa {};                   // Secret Key Authenticator/Verifier
  Key  key(Auth::KEYSIZE_AUTH); // Create a random key
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_falsify_plaintext )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // falsify the plaintext
  if (plainblob.size() != 0)
    ++plainblob[0];
  
  // the MAC must NOT verify
  BOOST_CHECK(! sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full_falsify_mac )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // falsify the MAC
  if (mac.size() != 0)
    ++mac[0];
  
  // the MAC must verify
  BOOST_CHECK(! sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty_falsify_mac )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // falsify the MAC
  if (mac.size() != 0)
    ++mac[0];
  
  // the MAC must verify
  BOOST_CHECK(! sa.verify(plainblob, mac, key));
}


BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full_falsify_key )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // create another key
  Key  key2(Auth::KEYSIZE_AUTH);
  BOOST_CHECK(key != key2); // very unlikely that they are equal!
  
  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa.verify(plainblob, mac, key2));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty_falsify_key )
{
  Auth sa {};
  Key  key(Auth::KEYSIZE_AUTH);

  std::string plaintext {};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // create another key
  Key  key2(Auth::KEYSIZE_AUTH);
  BOOST_CHECK(key != key2); // very unlikely that they are equal!
  
  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa.verify(plainblob, mac, key2));
}

BOOST_AUTO_TEST_SUITE_END ();
