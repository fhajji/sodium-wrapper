// test_Hash.cpp -- Test Sodium::Hash
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
#define BOOST_TEST_MODULE Sodium::Hash Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "hash.h"
#include <string>
#include <stdexcept>

using Sodium::Hash;
using Sodium::KeyVar;

using data_t = Sodium::data_t;

bool
test_hash_size(const std::string &plaintext,
	       const std::size_t hashsize)
{
  Hash::key_type key(hashsize);
  Hash           hasher {};
  
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    data_t outHash = hasher.hash(plainblob, key, hashsize);
    
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
  Hash::key_type key    (keysize);
  Hash           hasher {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    if (return_hash_as_value) {
      data_t outHash = hasher.hash(plainblob, key /* , Hash::HASHSIZE */ );
    }
    else {
      data_t outHash(Hash::HASHSIZE);
      hasher.hash(plainblob, key, outHash);
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
  Hash::key_type key1(Hash::KEYSIZE);
  Hash::key_type key2(Hash::KEYSIZE);
  Hash           hasher {};
  
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    data_t outHash1 = hasher.hash(plainblob, key1 /* , Hash::HASHSIZE */);
    data_t outHash2 = hasher.hash(plainblob, key2 /* , Hash::HASHSIZE */);
    
    return (key1 != key2) && (outHash1 != outHash2);
  }
  catch (std::exception & /* e */) {
    // test failed for some reason
    return false;
  }

  // NOTREACHED
  return false;
}

bool
test_keyless_hashing(const std::string &plaintext)
{
  Hash   hasher {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  try {
    data_t outHash1 = hasher.hash(plainblob /* , Hash::HASHSIZE */); // keyless
    data_t outHash2(Hash::HASHSIZE);
    hasher.hash(plainblob, outHash2); // keyless

    return outHash1 == outHash2;
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_hash_test_default_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, Hash::HASHSIZE));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_min_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, Hash::HASHSIZE_MIN));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_max_hash_size )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_hash_size(plaintext, Hash::HASHSIZE_MAX));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_hash_size_too_small )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, Hash::HASHSIZE_MIN-1));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_hash_size_too_big )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_hash_size(plaintext, Hash::HASHSIZE_MAX+1));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_default_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE, true));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_min_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE_MIN, true));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_max_key_size_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE_MAX, true));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_key_size_too_small_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, Hash::KEYSIZE_MIN-1, true));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_key_size_too_big_returnHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, Hash::KEYSIZE_MAX+1, true));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_default_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE, false));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_min_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE_MIN, false));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_max_key_size_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_key_size(plaintext, Hash::KEYSIZE_MAX, false));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_key_size_too_small_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, Hash::KEYSIZE_MIN-1, false));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_key_size_too_big_outHash )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(! test_key_size(plaintext, Hash::KEYSIZE_MAX+1, false));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_falsify_plaintext )
{
  Hash::key_type key(Hash::KEYSIZE);
  Hash           hasher {};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob { plaintext.cbegin(), plaintext.cend() };
  data_t      falsified { plainblob };
  ++falsified[0];
  
  data_t hash1 = hasher.hash(plainblob, key /* , Hash::HASHSIZE */);
  data_t hash2 = hasher.hash(falsified, key /* , Hash::HASHSIZE */);

  // unless there is a collision (very unlikely),
  // both hashes must be different for test to succeed
  BOOST_CHECK(hash1 != hash2);
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_same_full_plaintext_different_keys )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_same_empty_plaintext_different_keys )
{
  std::string plaintext {};

  BOOST_CHECK(test_different_keys(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_keyless_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(test_keyless_hashing(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_hash_test_keyless_empty_plaintext )
{
  std::string plaintext {};

  BOOST_CHECK(test_keyless_hashing(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
