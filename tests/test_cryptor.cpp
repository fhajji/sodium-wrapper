// test_cryptor.cpp -- Test sodium::cryptor
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
#define BOOST_TEST_MODULE sodium::cryptor Test
#include <boost/test/included/unit_test.hpp>

#include "cryptor.h"
#include <string>
#include <sodium.h>

using sodium::cryptor;
using bytes = sodium::bytes;

bool
test_of_correctness(const std::string &plaintext,
		    bool falsify_ciphertext=false,
		    bool falsify_mac=false,
		    bool falsify_key=false,
		    bool falsify_nonce=false)
{
  cryptor<>::key_type   key;
  cryptor<>::key_type   key2;
  cryptor<>::nonce_type nonce {};
  cryptor<>::nonce_type nonce2 {};

  cryptor<> sc{ std::move(key) };
  cryptor<> sc2{ std::move(key2) };

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() == cryptor<>::MACSIZE + plainblob.size());
  
  if (! plaintext.empty() && falsify_ciphertext) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[cryptor<>::MACSIZE]; // falsify ciphertext
  }
  
  if (falsify_mac) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[0]; // falsify MAC
  }

  try {
	bytes decrypted = (falsify_key ? sc2 : sc).decrypt(ciphertext, (falsify_nonce ? nonce2 : nonce));
	
    BOOST_CHECK(decrypted.size()  == plainblob.size());

    // decryption succeeded and plainblob == decrypted if and only if
    // we didn't falsify the ciphertext nor the MAC nor the key nor the nonce
    
    return !falsify_ciphertext &&
      !falsify_mac &&
      !falsify_key &&
      !falsify_nonce &&
      (plainblob == decrypted);
  }
  catch (std::exception & /* e */) {
    // decryption failed. This is expected if and only if we falsified
    // the ciphertext OR we falsified the MAC
    // OR we falsified the key
    // OR we falsified the nonce

    return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
  }

  // NOTREACHED (hopefully)
  return false;
}

bool
test_of_correctness_detached(const std::string &plaintext,
			     bool falsify_ciphertext=false,
			     bool falsify_mac=false,
			     bool falsify_key=false,
			     bool falsify_nonce=false)
{
  cryptor<> sc;  // with random key
  cryptor<> sc2; // with (another) random key
  cryptor<>::nonce_type nonce {};
  cryptor<>::nonce_type nonce2 {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  cryptor<>::bytes_type mac(cryptor<>::MACSIZE);

  // encrypt, using detached form
  bytes ciphertext = sc.encrypt(plainblob, nonce, mac);

  BOOST_CHECK(ciphertext.size() == plainblob.size());
  
  if (! plaintext.empty() && falsify_ciphertext)
    ++ciphertext[0]; // falsify ciphertext

  if (falsify_mac)
    ++mac[0]; // falsify MAC

  try {
	bytes decrypted = (falsify_key ? sc2 : sc).decrypt(
		  ciphertext,
		  mac,
		  (falsify_nonce ? nonce2 : nonce)
	);

    BOOST_CHECK(decrypted.size()  == plainblob.size());

    // decryption succeeded and plainblob == decrypted if and only if
    // we didn't falsify the ciphertext nor the MAC nor the key nor the nonce
    
    return !falsify_ciphertext &&
      !falsify_mac &&
      !falsify_key &&
      !falsify_nonce &&
      (plainblob == decrypted);
  }
  catch (std::exception & /* e */) {
    // decryption failed. This is expected if and only if we falsified
    // the ciphertext OR we falsified the MAC
    // OR falsified the key
    // OR falsified the nonce

    return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
  }

  // NOTREACHED (hopefully)
  return false;
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

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

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_ciphertext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, true, false, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_mac )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, false, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_key )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_nonce )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_mac_empty )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_ciphertext_and_mac )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, true, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_ciphertext_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, true, false, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_mac_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_key_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_nonce_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_mac_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_key_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_nonce_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_cryptor_test_falsify_ciphertext_and_mac_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, true, true, false, false));
}

BOOST_AUTO_TEST_SUITE_END ()
