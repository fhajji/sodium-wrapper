// test_authenticator.cpp -- Test sodium::authenticator
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
#define BOOST_TEST_MODULE sodium::authenticator Test
#include <boost/test/included/unit_test.hpp>

#include "authenticator.h"
#include "common.h"

#include <string>

using sodium::authenticator;
using bytes = sodium::bytes;

static constexpr std::size_t macsize = authenticator<>::MACSIZE;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_size )
{
  authenticator<> sa {}; // Secret Key Authenticator/Verifier
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  authenticator<>::bytes_type mac { sa.mac(plainblob) };

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE(sodium_test_auth_mac_size_key_copy)
{
	authenticator<>::key_type key{}; // create secret key
	authenticator<> sa{key}; // Secret Key Authenticator/Verifier

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	authenticator<>::bytes_type plainblob{ plaintext.cbegin(), plaintext.cend() };

	// compute the MAC
	authenticator<>::bytes_type mac{ sa.mac(plainblob) };

	BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE(sodium_test_auth_mac_size_key_move2)
{
	authenticator<> sa{ authenticator<>::key_type() }; // Secret Key Authenticator/Verifier

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	authenticator<>::bytes_type plainblob{ plaintext.cbegin(), plaintext.cend() };

	// compute the MAC
	authenticator<>::bytes_type mac{ sa.mac(plainblob) };

	BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE(sodium_test_auth_auth_copy)
{
	authenticator<> sa1;        // with random key
	authenticator<> sa2{ sa1 }; // copy

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	authenticator<>::bytes_type plainblob{ plaintext.cbegin(), plaintext.cend() };

	// compute the MAC
	auto mac1{ sa1.mac(plainblob) };
	auto mac2{ sa2.mac(plainblob) };

	BOOST_CHECK(mac1 == mac2);
}

BOOST_AUTO_TEST_CASE(sodium_test_auth_auth_move)
{
	authenticator<> sa1{}; // with random key

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	authenticator<>::bytes_type plainblob{ plaintext.cbegin(), plaintext.cend() };

	// compute the MAC
	auto mac1{ sa1.mac(plainblob) };

	// move sa1 to a new authenticator
	authenticator<> sa2{ std::move(sa1) };

	// recompute the MAC with the new authenticator
	auto mac2{ sa2.mac(plainblob) };

	BOOST_CHECK(mac1 == mac2);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full )
{
  authenticator<> sa {};

  std::string   plaintext {"the quick brown fox jumps over the lazy dog"};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa.mac(plainblob) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty )
{
  authenticator<> sa;

  std::string   plaintext {};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa.mac(plainblob) };

  // the MAC must verify
  BOOST_CHECK(sa.verify(plainblob, mac));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_falsify_plaintext )
{
  authenticator<> sa {};

  std::string   plaintext {"the quick brown fox jumps over the lazy dog"};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa.mac(plainblob) };

  // falsify the plaintext
  if (plainblob.size() != 0)
    ++plainblob[0];
  
  // the MAC must NOT verify
  BOOST_CHECK(! sa.verify(plainblob, mac));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full_falsify_mac )
{
  authenticator<> sa {};

  std::string   plaintext {"the quick brown fox jumps over the lazy dog"};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa.mac(plainblob) };

  // falsify the MAC
  if (mac.size() != 0)
    ++mac[0];
  
  // the MAC must verify
  BOOST_CHECK(! sa.verify(plainblob, mac));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty_falsify_mac )
{
  authenticator<> sa {};

  std::string   plaintext {};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa.mac(plainblob) };

  // falsify the MAC
  if (mac.size() != 0)
    ++mac[0];
  
  // the MAC must verify
  BOOST_CHECK(! sa.verify(plainblob, mac));
}


BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_full_falsify_key )
{
  authenticator<>::key_type key;
  authenticator<>           sa1 { key };

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac1 { sa1.mac(plainblob) };

  // create another key
  authenticator<>::key_type key2;
  BOOST_CHECK(key != key2); // very unlikely that they are equal!

  authenticator<> sa2{ std::move(key2) };
  
  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa2.verify(plainblob, mac1));
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_mac_verify_empty_falsify_key )
{
  authenticator<>::key_type key;
  authenticator<>           sa1{ key };

  std::string plaintext {};
  authenticator<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};

  // compute the MAC
  auto mac { sa1.mac(plainblob) };

  // create another key
  authenticator<>::key_type key2;
  BOOST_CHECK(key != key2); // very unlikely that they are equal!
  
  authenticator<> sa2{ std::move(key2) };

  // the MAC must NOT verify with key2
  BOOST_CHECK(! sa2.verify(plainblob, mac));
}

BOOST_AUTO_TEST_SUITE_END ()
