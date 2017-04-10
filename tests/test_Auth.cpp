// test_Auth.cpp -- Test Sodium::Auth
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
#define BOOST_TEST_MODULE Sodium::Auth Test
#include <boost/test/included/unit_test.hpp>

#include "auth.h"
#include "common.h"

#include <string>

using Sodium::Auth;
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
  Auth           sa {}; // Secret Key Authenticator/Verifier
  Auth::key_type key;   // Create a random key
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full )
{
  Auth           sa {};
  Auth::key_type key;

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty )
{
  Auth           sa {};
  Auth::key_type key;

  std::string plaintext {};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac, key));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_falsify_plaintext )
{
  Auth           sa {};
  Auth::key_type key;

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
  Auth           sa {};
  Auth::key_type key;

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
  Auth           sa {};
  Auth::key_type key;

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
  Auth           sa {};
  Auth::key_type key;

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // create another key
  Auth::key_type key2;
  BOOST_CHECK(key != key2); // very unlikely that they are equal!
  
  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa.verify(plainblob, mac, key2));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty_falsify_key )
{
  Auth           sa {};
  Auth::key_type key;

  std::string plaintext {};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  data_t      mac { sa.auth(plainblob, key) };

  // create another key
  Auth::key_type key2;
  BOOST_CHECK(key != key2); // very unlikely that they are equal!
  
  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa.verify(plainblob, mac, key2));
}

BOOST_AUTO_TEST_SUITE_END ();
