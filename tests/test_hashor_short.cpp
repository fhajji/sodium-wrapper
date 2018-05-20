// test_hashor_short.cpp -- Test sodium::hashor_short
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
#define BOOST_TEST_MODULE sodium::hashor_short Test
#include <boost/test/included/unit_test.hpp>

#include "hashor_short.h"
#include <string>
#include <stdexcept>
#include <sodium.h>

using bytes = sodium::bytes;
using sodium::hashor_short;

bool
test_hash_default_size(const std::string &plaintext)
{
  hashor_short<> hashor; // with a random key
  
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    bytes outHash = hashor.hash(plainblob);
    
    return outHash.size() == hashor_short<>::HASHSIZE;
  }
  catch (std::exception & /* e */) {
    // test failed for some reason
    return false;
  }

  // NOTREACHED
  BOOST_TEST_MESSAGE("test_hashor_short_default_size() fell off the cliff");
  BOOST_CHECK(false);
  return false;
}

bool
test_same_hashes(const std::string &plaintext)
{
  hashor_short<> hashor1{ hashor_short<>::key_type() }; // key moving version
  hashor_short<> hashor2{ hashor1 };                    // copying version

  hashor_short<>::bytes_type plainblob {plaintext.cbegin(), plaintext.cend()};
  hashor_short<>::bytes_type outHash(hashor_short<>::HASHSIZE);

  hashor1.hash(plainblob, outHash);
  auto outHash_returned = hashor2.hash(plainblob);

  return outHash == outHash_returned; // same content of the hashes
}

bool
test_hash_size(const std::string &plaintext,
	       const std::size_t hashsize)
{
  hashor_short<>::key_type key;
  hashor_short<>           hashor {std::move(key)}; // key-moving version

  bytes plainblob { plaintext.cbegin(), plaintext.cend() };
  bytes outHash(hashsize); // make it too big

  try {
    hashor.hash(plainblob, outHash);
    return true; // hashing was successful
  }
  catch (std::exception & /* e */) {
    // hashing threw because of wrong size
    return false;
  }

  // NOTREACHED
  BOOST_TEST_MESSAGE("test_hash_size() fell off the cliff");
  BOOST_CHECK(false);
  return false;
}

bool
test_different_keys(const std::string &plaintext)
{
  hashor_short<>::key_type key1;
  hashor_short<>::key_type key2;
  hashor_short<>           hashor1{ key1 }; // key-copying version
  hashor_short<>           hashor2{ key2 }; // key-coping version

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    auto outHash1 = hashor1.hash(plainblob);
    auto outHash2 = hashor2.hash(plainblob);
    
	// since we COPIED the keys while constructing
	// hashor2 and hashor2, they are still available
	// for comparison.
    return (key1 != key2) && (outHash1 != outHash2);
  }
  catch (std::exception & /* e */) {
    // test failed for some reason
    return false;
  }

  // NOTREACHED
  BOOST_TEST_MESSAGE("test_different_keys() fell off the cliff");
  BOOST_CHECK(false);
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

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_hash_default_size_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_default_size(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_hash_default_size_empty )
{
  std::string plaintext {};

  BOOST_CHECK(test_hash_default_size(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_same_hashes_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_same_hashes(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_same_hashes_empty )
{
  std::string plaintext {};

  BOOST_CHECK(test_same_hashes(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_falsify_plaintext )
{
  hashor_short<> hashor {};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes       plainblob { plaintext.cbegin(), plaintext.cend() };
  bytes       falsified { plainblob };
  ++falsified[0];
  
  bytes hash1 = hashor.hash(plainblob);
  bytes hash2 = hashor.hash(falsified); // reuse key

  // unless there is a collision (somewhat, but not entirely unlikely),
  // both hashes must be different for test to succeed
  BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_same_full_plaintext_different_keys )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_same_empty_plaintext_different_keys )
{
  std::string plaintext {};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_outHash_size_too_big )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, hashor_short<>::HASHSIZE+1));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_outHash_size_too_small )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, hashor_short<>::HASHSIZE-1));
}

BOOST_AUTO_TEST_CASE( sodium_hashshort_test_outHash_size_just_right )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, hashor_short<>::HASHSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_hashshort_test_move_hashors)
{
	hashor_short<> hashor1{};

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	bytes       plainblob{ plaintext.cbegin(), plaintext.cend() };

	bytes hash1 = hashor1.hash(plainblob);

	// move-construct hashor2 out of hashor1.
	// hashor1's key will std::move() to hashor2's key
	hashor_short<> hashor2{ std::move(hashor1) };

	bytes hash2 = hashor2.hash(plainblob);

	// since hash1 and hash2 were computed from the same key
	// and same plainblob, they MUST be equal.
	BOOST_CHECK(hash1 == hash2);
}

BOOST_AUTO_TEST_SUITE_END ()
