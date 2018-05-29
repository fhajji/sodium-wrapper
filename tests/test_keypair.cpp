// test_keypair.cpp -- Test sodium::keypair
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
#define BOOST_TEST_MODULE sodium::keypair Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "key.h"
#include "keypair.h"
#include "random.h"
#include "helpers.h"
#include <stdexcept>
#include <sodium.h>

using sodium::keypair;
using bytes = sodium::bytes;

static constexpr std::size_t ks_pub  = keypair<>::KEYSIZE_PUBLIC_KEY;
static constexpr std::size_t ks_priv = keypair<>::KEYSIZE_PRIVATE_KEY;
static constexpr std::size_t ks_seed = keypair<>::KEYSIZE_SEEDBYTES;

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

// 1. sodium::bytes -----------------------------------------------------------

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_default_bytes )
{
  keypair<> keypair {};

  BOOST_TEST(keypair.public_key().size() == ks_pub);
  BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_seed_bytes )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);
  
  keypair<> keypair(seed);

  BOOST_TEST(keypair.public_key().size() == ks_pub);
  BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_size_ctor_privkey_bytes )
{
  keypair<> keypair1 {};
  keypair<> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

  BOOST_TEST(keypair2.public_key().size() == ks_pub);
  BOOST_TEST(keypair2.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypair_copy_ctor_bytes )
{
  keypair<> keypair1 {};
  keypair<> keypair_copy {keypair1};

  // XXX Currenty broken
  // BOOST_TEST(keypair1 == keypair_copy); // check also operator==() on keypair(s)

  // BOOST_TEST(keypair1.private_key() == keypair_copy.private_key()); // key::operator==()
  BOOST_TEST(keypair1.public_key()  == keypair_copy.public_key());  // std::vector::operator==()
}

BOOST_AUTO_TEST_CASE ( sodium_test_keypair_copy_assignement_bytes )
{
  keypair<> keypair1 {};
  keypair<> keypair_copy = keypair1;

  // XXX Currently broken
  // BOOST_TEST(keypair1 == keypair_copy);

  // BOOST_TEST(keypair1.private_key() == keypair_copy.private_key());
  BOOST_TEST(keypair1.public_key()  == keypair_copy.public_key());
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_default_bytes )
{
  keypair<> keypair1 {};

  BOOST_TEST(! sodium::is_zero(keypair1.public_key()));
  BOOST_TEST(! sodium::is_zero(keypair1.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_seed_bytes )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);

  keypair<> keypair(seed);

  BOOST_TEST(!sodium::is_zero(keypair.public_key()));
  BOOST_TEST(!sodium::is_zero(keypair.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_nonzero_ctor_privkey_bytes )
{
  keypair<> keypair1 {};
  keypair<> keypair2 (keypair1.private_key().data(), keypair1.private_key().size());

  BOOST_TEST(!sodium::is_zero(keypair2.public_key()));
  BOOST_TEST(!sodium::is_zero(keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_default_bytes )
{
  keypair<> keypair;

  BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_seed_bytes )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);

  keypair<> keypair(seed);

  BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_different_ctor_privkey_bytes )
{
  keypair<> keypair1;
  keypair<> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

  BOOST_TEST(!sodium::compare(keypair2.public_key(), keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_seedcompare_ctor_same_seed_bytes )
{
  bytes seed(ks_seed);
  sodium::randombytes_buf_inplace(seed);

  keypair<> keypair1(seed);
  keypair<> keypair2(seed); // same seed

  BOOST_TEST(sodium::compare(keypair1.public_key(), keypair2.public_key()));
  BOOST_TEST(sodium::compare(keypair1.private_key(), keypair2.private_key()));
  
  // XXX Currently broken
  // BOOST_TEST(keypair1 == keypair2); // uses operator==() on keypairs
}

BOOST_AUTO_TEST_CASE( sodium_test_keypair_seedcompare_ctor_different_seed_bytes )
{
  bytes seed1{ sodium::randombytes_buf(ks_seed) };
  bytes seed2{ sodium::randombytes_buf(ks_seed) };

  BOOST_TEST(!sodium::compare(seed1, seed2)); // very unlikely that they are the same
  
  keypair<> keypair1(seed1);
  keypair<> keypair2(seed2); // different seed

  BOOST_TEST(!sodium::compare(keypair1.public_key(), keypair2.public_key()));
  BOOST_TEST(!sodium::compare(keypair1.private_key(), keypair2.private_key()));

  // XXX Currently broken
  // BOOST_TEST(keypair1 != keypair2); // check also operator!=()
}

// 2. sodium::bytes_protected ----------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_default_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair{};

	BOOST_TEST(keypair.public_key().size() == ks_pub);
	BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_seed_bytes_protected)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::bytes_protected> keypair(seed);

	BOOST_TEST(keypair.public_key().size() == ks_pub);
	BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_privkey_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1{};
	keypair<sodium::bytes_protected> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(keypair2.public_key().size() == ks_pub);
	BOOST_TEST(keypair2.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_copy_ctor_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1{};
	keypair<sodium::bytes_protected> keypair_copy{ keypair1 };

	// XXX Currenty broken
	// BOOST_TEST(keypair1 == keypair_copy); // check also operator==() on keypair(s)

	// BOOST_TEST(keypair1.private_key() == keypair_copy.private_key()); // key::operator==()
	BOOST_TEST(keypair1.public_key() == keypair_copy.public_key());  // std::vector::operator==()
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_copy_assignement_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1{};
	keypair<sodium::bytes_protected> keypair_copy = keypair1;

	// XXX Currently broken
	// BOOST_TEST(keypair1 == keypair_copy);

	// BOOST_TEST(keypair1.private_key() == keypair_copy.private_key());
	BOOST_TEST(keypair1.public_key() == keypair_copy.public_key());
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_default_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1{};

	BOOST_TEST(!sodium::is_zero(keypair1.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair1.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_seed_bytes_protected)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::bytes_protected> keypair(seed);

	BOOST_TEST(!sodium::is_zero(keypair.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_privkey_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1{};
	keypair<sodium::bytes_protected> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(!sodium::is_zero(keypair2.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_default_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair;

	BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_seed_bytes_protected)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::bytes_protected> keypair(seed);

	BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_privkey_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair1;
	keypair<sodium::bytes_protected> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(!sodium::compare(keypair2.public_key(), keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_seedcompare_ctor_same_seed_bytes_protected)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::bytes_protected> keypair1(seed);
	keypair<sodium::bytes_protected> keypair2(seed); // same seed

	BOOST_TEST(sodium::compare(keypair1.public_key(), keypair2.public_key()));
	BOOST_TEST(sodium::compare(keypair1.private_key(), keypair2.private_key()));

	// XXX Currently broken
	// BOOST_TEST(keypair1 == keypair2); // uses operator==() on keypairs
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_seedcompare_ctor_different_seed_bytes_protected)
{
	bytes seed1{ sodium::randombytes_buf(ks_seed) };
	bytes seed2{ sodium::randombytes_buf(ks_seed) };

	BOOST_TEST(!sodium::compare(seed1, seed2)); // very unlikely that they are the same

	keypair<sodium::bytes_protected> keypair1(seed1);
	keypair<sodium::bytes_protected> keypair2(seed2); // different seed

	BOOST_TEST(!sodium::compare(keypair1.public_key(), keypair2.public_key()));
	BOOST_TEST(!sodium::compare(keypair1.private_key(), keypair2.private_key()));

	// XXX Currently broken
	// BOOST_TEST(keypair1 != keypair2); // check also operator!=()
}

// 3. sodium::chars --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_default_chars)
{
	keypair<sodium::chars> keypair{};

	BOOST_TEST(keypair.public_key().size() == ks_pub);
	BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_seed_chars)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::chars> keypair(seed);

	BOOST_TEST(keypair.public_key().size() == ks_pub);
	BOOST_TEST(keypair.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_size_ctor_privkey_chars)
{
	keypair<sodium::chars> keypair1{};
	keypair<sodium::chars> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(keypair2.public_key().size() == ks_pub);
	BOOST_TEST(keypair2.private_key().size() == ks_priv);
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_copy_ctor_chars)
{
	keypair<sodium::chars> keypair1{};
	keypair<sodium::chars> keypair_copy{ keypair1 };

	// XXX Currenty broken
	// BOOST_TEST(keypair1 == keypair_copy); // check also operator==() on keypair(s)

	// BOOST_TEST(keypair1.private_key() == keypair_copy.private_key()); // key::operator==()
	BOOST_TEST(keypair1.public_key() == keypair_copy.public_key());  // std::vector::operator==()
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_copy_assignement_chars)
{
	keypair<sodium::chars> keypair1{};
	keypair<sodium::chars> keypair_copy = keypair1;

	// XXX Currently broken
	// BOOST_TEST(keypair1 == keypair_copy);

	// BOOST_TEST(keypair1.private_key() == keypair_copy.private_key());
	BOOST_TEST(keypair1.public_key() == keypair_copy.public_key());
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_default_chars)
{
	keypair<sodium::chars> keypair1{};

	BOOST_TEST(!sodium::is_zero(keypair1.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair1.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_seed_chars)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::chars> keypair(seed);

	BOOST_TEST(!sodium::is_zero(keypair.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_nonzero_ctor_privkey_chars)
{
	keypair<sodium::chars> keypair1{};
	keypair<sodium::chars> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(!sodium::is_zero(keypair2.public_key()));
	BOOST_TEST(!sodium::is_zero(keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_default_chars)
{
	keypair<sodium::chars> keypair;

	BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_seed_chars)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::chars> keypair(seed);

	BOOST_TEST(!sodium::compare(keypair.public_key(), keypair.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_different_ctor_privkey_chars)
{
	keypair<sodium::chars> keypair1;
	keypair<sodium::chars> keypair2(keypair1.private_key().data(), keypair1.private_key().size());

	BOOST_TEST(!sodium::compare(keypair2.public_key(), keypair2.private_key()));
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_seedcompare_ctor_same_seed_chars)
{
	bytes seed(ks_seed);
	sodium::randombytes_buf_inplace(seed);

	keypair<sodium::chars> keypair1(seed);
	keypair<sodium::chars> keypair2(seed); // same seed

	BOOST_TEST(sodium::compare(keypair1.public_key(), keypair2.public_key()));
	BOOST_TEST(sodium::compare(keypair1.private_key(), keypair2.private_key()));

	// XXX Currently broken
	// BOOST_TEST(keypair1 == keypair2); // uses operator==() on keypairs
}

BOOST_AUTO_TEST_CASE(sodium_test_keypair_seedcompare_ctor_different_seed_chars)
{
	bytes seed1{ sodium::randombytes_buf(ks_seed) };
	bytes seed2{ sodium::randombytes_buf(ks_seed) };

	BOOST_TEST(!sodium::compare(seed1, seed2)); // very unlikely that they are the same

	keypair<sodium::chars> keypair1(seed1);
	keypair<sodium::chars> keypair2(seed2); // different seed

	BOOST_TEST(!sodium::compare(keypair1.public_key(), keypair2.public_key()));
	BOOST_TEST(!sodium::compare(keypair1.private_key(), keypair2.private_key()));

	// XXX Currently broken
	// BOOST_TEST(keypair1 != keypair2); // check also operator!=()
}

BOOST_AUTO_TEST_SUITE_END ()
