// test_KeyPair.cpp -- Test Sodium::KeyPair
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
#define BOOST_TEST_MODULE Sodium::KeyPair Test
#include <boost/test/included/unit_test.hpp>

#include <algorithm>
#include <stdexcept>

#include <sodium.h>

#include "common.h"
#include "key.h"
#include "keypair.h"

using Sodium::Key;
using Sodium::KeyPair;
using data_t = Sodium::data_t;

static constexpr std::size_t ks_pub  = KeyPair::KEYSIZE_PUBKEY;
static constexpr std::size_t ks_priv = KeyPair::KEYSIZE_PRIVKEY;
static constexpr std::size_t ks_seed = KeyPair::KEYSIZE_SEEDBYTES;

bool isAllZero(const unsigned char *bytes, const std::size_t &size)
{
  return std::all_of(bytes, bytes+size,
		     [](unsigned char byte){return byte == '\0';});
}

bool isSameBytes(const unsigned char *bytes1, const std::size_t &size1,
		 const unsigned char *bytes2, const std::size_t &size2)
{
  if (size1 != size2)
    throw std::runtime_error {"isSameBytes(): not same size"};

  return std::equal(bytes1, bytes1+size1,
		    bytes2);
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

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_default )
{
  KeyPair keypair {};

  BOOST_CHECK_EQUAL(keypair.pubkey_size(), ks_pub);
  BOOST_CHECK_EQUAL(keypair.privkey_size(), ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_seed )
{
  data_t  seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());
  
  KeyPair keypair(seed);

  BOOST_CHECK_EQUAL(keypair.pubkey_size(), ks_pub);
  BOOST_CHECK_EQUAL(keypair.privkey_size(), ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_privkey )
{
  KeyPair keypair1 {};
  KeyPair keypair2(keypair1.privkey_data(), keypair1.privkey_size());

  BOOST_CHECK_EQUAL(keypair2.pubkey_size(),  ks_pub);
  BOOST_CHECK_EQUAL(keypair2.privkey_size(), ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_default )
{
  KeyPair keypair {};

  BOOST_CHECK (! isAllZero(keypair.pubkey_data(), keypair.pubkey_size()));
  BOOST_CHECK (! isAllZero(keypair.privkey_data(), keypair.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_seed )
{
  data_t seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());

  KeyPair keypair(seed);

  BOOST_CHECK(! isAllZero(keypair.pubkey_data(), keypair.pubkey_size()));
  BOOST_CHECK(! isAllZero(keypair.privkey_data(), keypair.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_privkey )
{
  KeyPair keypair1 {};
  KeyPair keypair2(keypair1.privkey_data(), keypair1.privkey_size());

  BOOST_CHECK(! isAllZero(keypair2.pubkey_data(), keypair2.pubkey_size()));
  BOOST_CHECK(! isAllZero(keypair2.privkey_data(), keypair2.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_default )
{
  KeyPair keypair {};

  BOOST_CHECK(! isSameBytes(keypair.pubkey_data(), keypair.pubkey_size(),
			    keypair.privkey_data(), keypair.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_seed )
{
  data_t seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());

  KeyPair keypair(seed);

  BOOST_CHECK(! isSameBytes(keypair.pubkey_data(), keypair.pubkey_size(),
			    keypair.privkey_data(), keypair.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_privkey )
{
  KeyPair keypair1 {};
  KeyPair keypair2(keypair1.privkey_data(), keypair1.privkey_size());

  BOOST_CHECK(! isSameBytes(keypair2.pubkey_data(), keypair2.pubkey_size(),
			    keypair2.privkey_data(), keypair2.privkey_size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_seedcompare_ctor_same_seed )
{
  data_t seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());

  KeyPair keypair1(seed);
  KeyPair keypair2(seed); // same seed

  BOOST_CHECK(isSameBytes(keypair1.pubkey_data(), keypair1.pubkey_size(),
			  keypair2.pubkey_data(), keypair2.pubkey_size()));
  BOOST_CHECK(isSameBytes(keypair1.privkey_data(), keypair1.privkey_size(),
			  keypair2.privkey_data(), keypair2.privkey_size()));
  
  BOOST_CHECK(keypair1 == keypair2); // check also operator==()
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_seedcompare_ctor_different_seed )
{
  data_t seed1(ks_seed);
  randombytes_buf(seed1.data(), seed1.size());
  data_t seed2(ks_seed);
  randombytes_buf(seed2.data(), seed2.size());

  BOOST_CHECK(seed1 != seed2); // very unlikely that they are the same
  
  KeyPair keypair1(seed1);
  KeyPair keypair2(seed2); // different seed

  BOOST_CHECK(! isSameBytes(keypair1.pubkey_data(), keypair1.pubkey_size(),
			    keypair2.pubkey_data(), keypair2.pubkey_size()));
  BOOST_CHECK(! isSameBytes(keypair1.privkey_data(), keypair1.privkey_size(),
			    keypair2.privkey_data(), keypair2.privkey_size()));

  BOOST_CHECK(keypair1 != keypair2); // check also operator!=()
}

BOOST_AUTO_TEST_SUITE_END ();
