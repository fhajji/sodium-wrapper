// test_KeyPairSign.cpp -- Test sodium::KeyPairSign
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
#define BOOST_TEST_MODULE sodium::KeyPairSign Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "keypairsign.h"
#include <stdexcept>
#include <sodium.h>

using sodium::KeyPairSign;
using bytes = sodium::bytes;

static constexpr std::size_t ks_pub  = KeyPairSign::KEYSIZE_PUBKEY;
static constexpr std::size_t ks_priv = KeyPairSign::KEYSIZE_PRIVKEY;
static constexpr std::size_t ks_seed = KeyPairSign::KEYSIZE_SEEDBYTES;

bool isAllZero(const unsigned char *bytes, const std::size_t &size)
{
  // Don't do this (side channel attack):
  // return std::all_of(bytes, bytes+size,
  // 		     [](unsigned char byte){return byte == '\0';});

  // Compare in constant time instead:
  return sodium_is_zero(bytes, size);
}

bool isSameBytes(const unsigned char *bytes1, const std::size_t &size1,
		 const unsigned char *bytes2, const std::size_t &size2)
{
  if (size1 != size2)
    throw std::runtime_error {"isSameBytes(): not same size"};

  // Don't do this (side channel attack):
  //   return std::equal(bytes1, bytes1+size1,
  // 		    bytes2);

  // Compare in constant time instead:
  return (sodium_memcmp(bytes1, bytes2, size1) == 0);
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

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_default )
{
  KeyPairSign keypair {};

  BOOST_CHECK_EQUAL(keypair.pubkey().size(), ks_pub);
  BOOST_CHECK_EQUAL(keypair.privkey().size(), ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_seed )
{
  bytes seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());
  
  KeyPairSign keypair(seed);

  BOOST_CHECK_EQUAL(keypair.pubkey().size(), ks_pub);
  BOOST_CHECK_EQUAL(keypair.privkey().size(), ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_privkey )
{
  KeyPairSign keypair1 {};
  KeyPairSign keypair2(keypair1.privkey().data(), keypair1.privkey().size());

  BOOST_CHECK_EQUAL(keypair2.pubkey().size(),  ks_pub);
  BOOST_CHECK_EQUAL(keypair2.privkey().size(), ks_priv);
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypairsign_copy_ctor )
{
  KeyPairSign keypair {};
  KeyPairSign keypair_copy {keypair};

  BOOST_CHECK(keypair == keypair_copy); // check also operator==()
  BOOST_CHECK(keypair.privkey() == keypair_copy.privkey()); // Key::operator==()
  BOOST_CHECK(keypair.pubkey()  == keypair_copy.pubkey());  // std::vector::operator==()
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypairsign_copy_assignement )
{
  KeyPairSign keypair {};
  KeyPairSign keypair_copy = keypair;

  BOOST_CHECK(keypair == keypair_copy);
  BOOST_CHECK(keypair.privkey() == keypair_copy.privkey());
  BOOST_CHECK(keypair.pubkey()  == keypair_copy.pubkey());
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_default )
{
  KeyPairSign keypair {};

  BOOST_CHECK (! isAllZero(keypair.pubkey().data(), keypair.pubkey().size()));
  BOOST_CHECK (! isAllZero(keypair.privkey().data(), keypair.privkey().size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_seed )
{
  bytes seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());

  KeyPairSign keypair(seed);

  BOOST_CHECK(! isAllZero(keypair.pubkey().data(), keypair.pubkey().size()));
  BOOST_CHECK(! isAllZero(keypair.privkey().data(), keypair.privkey().size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_privkey )
{
  KeyPairSign keypair1 {};
  KeyPairSign keypair2(keypair1.privkey().data(), keypair1.privkey().size());

  BOOST_CHECK(! isAllZero(keypair2.pubkey().data(), keypair2.pubkey().size()));
  BOOST_CHECK(! isAllZero(keypair2.privkey().data(), keypair2.privkey().size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_ctor_same_seed )
{
  bytes seed(ks_seed);
  randombytes_buf(seed.data(), seed.size());

  KeyPairSign keypair1(seed);
  KeyPairSign keypair2(seed); // same seed

  BOOST_CHECK(isSameBytes(keypair1.pubkey().data(), keypair1.pubkey().size(),
			  keypair2.pubkey().data(), keypair2.pubkey().size()));
  BOOST_CHECK(isSameBytes(keypair1.privkey().data(), keypair1.privkey().size(),
			  keypair2.privkey().data(), keypair2.privkey().size()));
  
  BOOST_CHECK(keypair1 == keypair2); // check also operator==()
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_ctor_different_seed )
{
  bytes seed1(ks_seed);
  randombytes_buf(seed1.data(), seed1.size());
  bytes seed2(ks_seed);
  randombytes_buf(seed2.data(), seed2.size());

  BOOST_CHECK(seed1 != seed2); // very unlikely that they are the same
  
  KeyPairSign keypair1(seed1);
  KeyPairSign keypair2(seed2); // different seed

  BOOST_CHECK(! isSameBytes(keypair1.pubkey().data(), keypair1.pubkey().size(),
			    keypair2.pubkey().data(), keypair2.pubkey().size()));
  BOOST_CHECK(! isSameBytes(keypair1.privkey().data(), keypair1.privkey().size(),
			    keypair2.privkey().data(), keypair2.privkey().size()));

  BOOST_CHECK(keypair1 != keypair2); // check also operator!=()
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_extract_seed )
{
  bytes seed1(ks_seed);
  randombytes_buf(seed1.data(), seed1.size());

  KeyPairSign keypair(seed1);

  // reconstruct seed from private key stored in keypair
  bytes seed2 = keypair.seed();

  BOOST_CHECK(seed1 == seed2);
}

BOOST_AUTO_TEST_SUITE_END ()
