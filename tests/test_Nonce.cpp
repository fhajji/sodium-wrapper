// test_Nonce.cpp -- Test Sodium::Nonce<>
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_nonce_defaultsize )
{
  Sodium::Nonce<> a {};

  BOOST_CHECK_EQUAL(a.size(), Sodium::NONCESIZE_SECRETBOX);
}

BOOST_AUTO_TEST_CASE( sodium_test_nonce_size )
{
  Sodium::Nonce<64> a {};

  BOOST_CHECK_EQUAL(a.size(), 64);
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

  BOOST_CHECK(a != b); // may fail in very rare cases (1 out of 2^64 cases)
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
  
  for (int i: {1,2,3,4,5})
    a.increment();

  // The compare checks, except for == and !=, may fail in rare
  // cases, if wrap around occurs. But that is very rare with
  // huge number of bytes for the nonces.
  
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
  // valid initial nonce value. But this is extremely unlikely for
  // large enough values of nonces.
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
    a.increment();
    five.increment();
  }

  // 2. add 'five' to 'b' with += operator (in constant time)
  b += five;

  // 3. a+5 == b+5
  BOOST_CHECK(a == b);
}

BOOST_AUTO_TEST_SUITE_END ();
