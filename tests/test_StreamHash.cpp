// test_StreamHash.cpp -- Test Sodium::StreamHash
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
#define BOOST_TEST_MODULE Sodium::StreamHash Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "streamhash.h"
#include "keyvar.h"
#include <string>
#include <algorithm>
#include <sstream>

using Sodium::KeyVar;
using Sodium::StreamHash;
using data_t = Sodium::data_t;

constexpr static std::size_t hashsize  = StreamHash::HASHSIZE;
constexpr static std::size_t keysize   = StreamHash::KEYSIZE;
constexpr static std::size_t blocksize = 8;

bool
falsify_plaintext(const std::string &plaintext)
{
  // before even bothering falsifying a signed plaintext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");

  StreamHash::key_type key    (StreamHash::KEYSIZE);
  StreamHash           hasher {key, hashsize, blocksize};
  
  std::istringstream istr(plaintext);
  
  // hash that stream
  data_t hash1 = hasher.hash(istr);

  BOOST_CHECK_EQUAL(hash1.size(), hashsize);

  // falsify plaintext
  std::string falsifiedtext(plaintext);
  ++falsifiedtext[0];
  std::istringstream istr_falsified(falsifiedtext);

  // inverse logic: hashing the falsified text
  // with the same key and hashsize
  // MUST NOT yield the same hashes for the test to succeed.

  data_t hash2(hashsize);
  hasher.hash(istr_falsified, hash2);

  return hash1 != hash2;
}

bool
falsify_key(const std::string &plaintext)
{
  StreamHash::key_type key    (StreamHash::KEYSIZE);
  StreamHash           hasher {key, hashsize, blocksize};
  
  std::istringstream istr(plaintext);
  
  // hash that stream
  data_t hash1 = hasher.hash(istr);

  BOOST_CHECK_EQUAL(hash1.size(), hashsize);

  // to simulate falsification of key, just hash with a different key.
  StreamHash::key_type key_falsified    (StreamHash::KEYSIZE);
  StreamHash           hasher_falsified {key_falsified, hashsize, blocksize};

  std::istringstream istr_copy(plaintext);

  // inverse logic: hashing the same plaintext / stream
  // with a different / falsified key (and same hashsize)
  // MUST NOT yield the same hashes for the test to succeed.

  data_t hash2(hashsize);
  hasher_falsified.hash(istr_copy, hash2);

  return hash1 != hash2;
}

bool
compare_both_hashes(const std::string &plaintext)
{
  StreamHash::key_type key    (StreamHash::KEYSIZE);
  StreamHash           hasher {key, hashsize, blocksize};
  
  std::istringstream istr(plaintext);
  std::istringstream istr_copy(plaintext);
  
  // hash that stream both ways
  data_t hash1 = hasher.hash(istr);
  data_t hash2(hashsize);
  hasher.hash(istr_copy, hash2);

  // test succeeded if both hashes are equal
  return hash1 == hash2;
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

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_falsify_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_plaintext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_falsify_key_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_key(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_falsify_key_empty_plaintext )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_key(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_compare_hashes_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(compare_both_hashes(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_compare_hashes_small_plaintext )
{
  std::string plaintext {"little"};
  BOOST_CHECK(plaintext.size() < hashsize);

  BOOST_CHECK(compare_both_hashes(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamhash_test_compare_hashes_empty_plaintext )
{
  std::string plaintext {};

  BOOST_CHECK(compare_both_hashes(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
