// test_hashor_generic.cpp -- Test sodium::hashor_generic<>
//
// ISC License
// 
// Copyright (c) 2018 Farid Hajji <farid@hajji.name>
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
#define BOOST_TEST_MODULE sodium::hashor_generic Test
#include <boost/test/included/unit_test.hpp>

#include "hashor_generic.h"
#include <string>
#include <stdexcept>
#include <sodium.h>

using sodium::KeyVar;

using bytes  = sodium::bytes;
using hashor_generic = sodium::hashor_generic<bytes>;

bool
test_hash_size(const std::string &plaintext,
	       const std::size_t hashsize)
{
  hashor_generic hashor; // with a random key of default length
  
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    bytes outHash = hashor.hash(plainblob, hashsize);
    
    return outHash.size() == hashsize;
  }
  catch (std::exception & /* e */) {
    // test failed for some reason
    return false;
  }

  // NOTREACHED
  return false;
}

bool
test_key_size(const std::string &plaintext,
	      const std::size_t keysize,
	      bool  return_hash_as_value=true)
{
  try {
    hashor_generic::key_type key    (keysize);
    hashor_generic           hashor {std::move(key)}; // explicit moving version

    bytes plainblob {plaintext.cbegin(), plaintext.cend()};

    if (return_hash_as_value) {
      bytes outHash = hashor.hash(plainblob /* , hashor_generic::HASHSIZE */ );
    }
    else {
      bytes outHash(hashor_generic::HASHSIZE);
      hashor.hash(plainblob, outHash);
    }

    return true; // hashing succeeded. test ok.
  }
  catch (std::exception & /* e */) {
    // test failed for some reason (likely key size too small or too big)
    return false;
  }

  // NOTREACHED
  return false;
}

bool
test_different_keys(const std::string &plaintext)
{
  hashor_generic hashor1{ hashor_generic::key_type(hashor_generic::KEYSIZE) }; // moving version
  hashor_generic hashor2{ hashor_generic::key_type(hashor_generic::KEYSIZE) }; // moving version
  
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    bytes outHash1 = hashor1.hash(plainblob /* , hashor_generic::HASHSIZE */);
    bytes outHash2 = hashor2.hash(plainblob /* , hashor_generic::HASHSIZE */);
    
	// very unlikely that hashor1 and hashor2 have the same key
    return outHash1 != outHash2;
  }
  catch (std::exception & /* e */) {
    // test failed for some reason
    return false;
  }

  // NOTREACHED
  return false;
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_default_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, hashor_generic::HASHSIZE));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_min_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, hashor_generic::HASHSIZE_MIN));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_max_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, hashor_generic::HASHSIZE_MAX));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_hash_size_too_small )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, hashor_generic::HASHSIZE_MIN-1));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_hash_size_too_big )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, hashor_generic::HASHSIZE_MAX+1));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_default_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE, true));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_min_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE_MIN, true));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_max_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE_MAX, true));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_key_size_too_small_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, hashor_generic::KEYSIZE_MIN-1, true));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_key_size_too_big_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, hashor_generic::KEYSIZE_MAX+1, true));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_default_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE, false));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_min_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE_MIN, false));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_max_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, hashor_generic::KEYSIZE_MAX, false));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_key_size_too_small_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, hashor_generic::KEYSIZE_MIN-1, false));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_key_size_too_big_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, hashor_generic::KEYSIZE_MAX+1, false));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_falsify_plaintext )
{
  hashor_generic::key_type key(hashor_generic::KEYSIZE);
  hashor_generic           hashor {key}; // copying version

  std::string        plaintext {"the quick brown fox jumps over the lazy dog"};
  hashor_generic::bytes_type plainblob { plaintext.cbegin(), plaintext.cend() };
  hashor_generic::bytes_type falsified { plainblob };
  ++falsified[0];
  
  bytes hash1 = hashor.hash(plainblob /* , hashor_generic::HASHSIZE */);
  bytes hash2 = hashor.hash(falsified /* , hashor_generic::HASHSIZE */);

  // unless there is a collision (very unlikely),
  // both hashes must be different for test to succeed
  BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_same_full_plaintext_different_keys )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hashor_generic_test_same_empty_plaintext_different_keys )
{
  std::string plaintext {};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ()
