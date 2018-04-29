// test_Nonce.cpp -- Test Sodium::Nonce<>
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
#define BOOST_TEST_MODULE Sodium::Nonce Test
#include <boost/test/included/unit_test.hpp>

#include "nonce.h"

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

BOOST_AUTO_TEST_CASE( sodium_test_nonce_defaultsize )
{
  Sodium::Nonce<> a {};

  BOOST_CHECK_EQUAL(a.size(), Sodium::NONCESIZE_SECRETBOX);
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_size )
{
  Sodium::Nonce<64>  a {};
  Sodium::Nonce<128> b {};

  BOOST_CHECK_EQUAL(a.size(), 64);
  BOOST_CHECK_EQUAL(b.size(), 128);

  static_assert(a.size() == 64,
		"a is not 64 bytes long");
  static_assert(b.size() == 128,
		"b is not 128 bytes long");
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_copy )
{
  Sodium::Nonce<> a {};
  Sodium::Nonce<> a_copy {a};

  BOOST_CHECK(a == a_copy); // check operator== in constant time
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_assignment )
{
  Sodium::Nonce<64> a {};
  Sodium::Nonce<64> b {};

  BOOST_CHECK(a != b); // may fail in very rare cases (1 out of 2^{8*64} cases)
  a = b;
  BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_increment_compare )
{
  Sodium::Nonce<> a {};
  Sodium::Nonce<> a_copy {a};

  BOOST_CHECK(a == a_copy);      // check operator==
  BOOST_CHECK(! (a != a_copy));  // check operator!=

  BOOST_CHECK(! (a < a_copy));   // check operator<
  BOOST_CHECK(! (a > a_copy));   // check operator>

  BOOST_CHECK(a <= a_copy);      // check operator<=
  BOOST_CHECK(a >= a_copy);      // check operator>=

  BOOST_CHECK_EQUAL(Sodium::compare(a, a_copy), 0);
  
  for (int i: {1,2,3,4,5}) {
    static_cast<void>(i); // "use" unused variable i
    a.increment();
  }
  
  // The compare checks, except for == and !=, may fail in rare
  // cases, if wrap around occurs. But that is rare with the
  // nonces having the default number of bytes.
  
  BOOST_CHECK(! (a == a_copy));
  BOOST_CHECK(a != a_copy);

  BOOST_CHECK(a > a_copy);
  BOOST_CHECK(a_copy < a);

  BOOST_CHECK(a >= a_copy);
  BOOST_CHECK(! (a <= a_copy));

  BOOST_CHECK_EQUAL(Sodium::compare(a, a_copy), 1);
  BOOST_CHECK_EQUAL(Sodium::compare(a_copy, a), -1);
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_init_nonzero )
{
  Sodium::Nonce<> a {};

  // In rare cases, this check could fail, because all-zeroes is a
  // valid initial nonce value. It can happen once in every
  // 2^{8*Sodium::NONCESIZE_SECRETBOX} cases.

  BOOST_CHECK(! a.is_zero());
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_init_zero )
{
  Sodium::Nonce<> a(false); // non-initialized nonce...

  BOOST_CHECK(a.is_zero()); // ... must be all-zeroes.
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_operator_plus_equal )
{
  Sodium::Nonce<128> a {};
  Sodium::Nonce<128> b {a};
  Sodium::Nonce<128> five(false); // all-zeroes
  
  BOOST_CHECK(a == b);

  // 1. increment 'a' and 'five' 5 times:
  for (int i: {1,2,3,4,5}) {
    static_cast<void>(i); // "use" unused variable i
    a.increment();
    five.increment();
  }

  // 2. add 'five' to 'b' with += operator (in constant time)
  b += five;

  // 3. a+5 == b+5
  BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_SUITE_END ()
