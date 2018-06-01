// test_keypairsign.cpp -- Test sodium::keypairsign
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
#define BOOST_TEST_MODULE sodium::keypairsign Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "keypairsign.h"
#include "helpers.h"
#include "random.h"
#include <stdexcept>
#include <sodium.h>

using sodium::keypairsign;
using bytes = sodium::bytes;

static constexpr std::size_t ks_pub  = keypairsign<>::KEYSIZE_PUBLIC_KEY;
static constexpr std::size_t ks_priv = keypairsign<>::KEYSIZE_PRIVATE_KEY;
static constexpr std::size_t ks_seed = keypairsign<>::KEYSIZE_SEEDBYTES;

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

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_default )
{
  keypairsign<> keypair;

  BOOST_TEST(keypair.public_key().size() == ks_pub);
  BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_seed )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);
  
  keypairsign<> keypair(seed);

  BOOST_TEST(keypair.public_key().size() == ks_pub);
  BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_size_ctor_privkey )
{
  keypairsign<> keypair1;
  keypairsign<> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

  BOOST_TEST(keypair2.public_key().size() == ks_pub);
  BOOST_TEST(keypair2.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypairsign_copy_ctor )
{
  keypairsign<> keypair;
  keypairsign<> keypair_copy {keypair};

  // BOOST_TEST(keypair == keypair_copy); // check also operator==()
  // BOOST_TEST(keypair.private_key() == keypair_copy.private_key()); // key::operator==()
  BOOST_TEST(keypair.public_key()  == keypair_copy.public_key());  // std::vector::operator==()
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypairsign_copy_assignement )
{
  keypairsign<> keypair;
  keypairsign<> keypair_copy = keypair;

  // BOOST_TEST(keypair == keypair_copy);
  // BOOST_TEST(keypair.private_key() == keypair_copy.private_key());
  BOOST_TEST(keypair.public_key()  == keypair_copy.public_key());
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_default )
{
  keypairsign<> keypair;

  BOOST_TEST(!sodium::is_zero(keypair.public_key()));
  BOOST_TEST(!sodium::is_zero(keypair.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_seed )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);

  keypairsign<> keypair(seed);

  BOOST_TEST(!sodium::is_zero(keypair.public_key()));
  BOOST_TEST(!sodium::is_zero(keypair.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_nonzero_ctor_privkey )
{
  keypairsign<> keypair1;
  keypairsign<> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

  BOOST_TEST(!sodium::is_zero(keypair2.public_key()));
  BOOST_TEST(!sodium::is_zero(keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_ctor_same_seed )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);

  keypairsign<> keypair1(seed);
  keypairsign<> keypair2(seed); // same seed

  BOOST_TEST(sodium::compare(keypair1.public_key(),
	  keypair2.public_key()));
  BOOST_TEST(sodium::compare(keypair1.private_key(),
	  keypair2.private_key()));
  
  // BOOST_TEST(keypair1 == keypair2); // check also operator==()
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_ctor_different_seed )
{
  bytes seed1(ks_seed);
  sodium::randombytes_buf_inplace(seed1);
  bytes seed2(ks_seed);
  sodium::randombytes_buf_inplace(seed2);

  BOOST_TEST(seed1 != seed2); // very unlikely that they are the same
  
  keypairsign<> keypair1(seed1);
  keypairsign<> keypair2(seed2); // different seed

  BOOST_TEST(!sodium::compare(keypair1.public_key(),
	  keypair2.public_key()));
  BOOST_TEST(!sodium::compare(keypair1.private_key(),
	  keypair2.private_key()));

  // BOOST_TEST(keypair1 != keypair2); // check also operator!=()
}

BOOST_AUTO_TEST_CASE( sodium_test_keypairsign_seedcompare_extract_seed )
{
  bytes seed1(ks_seed);
  sodium::randombytes_buf_inplace(seed1);

  keypairsign<> keypair(seed1);

  // reconstruct seed from private key stored in keypair
  bytes seed2 = keypair.seed();

  BOOST_TEST(seed1 == seed2);
}

BOOST_AUTO_TEST_SUITE_END ()
