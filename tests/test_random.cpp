// test_random.cpp -- Test CSRNG's wrappers
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

// To see test messages, including timing results:
//    ./test_random --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::random Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "helpers.h"
#include "random.h"
#include <array>
#include <string>
#include <typeinfo>
#include <vector>

struct SodiumFixture
{
    SodiumFixture()
    {
        BOOST_REQUIRE(sodium_init() != -1);
        // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
    }
    ~SodiumFixture()
    {
        // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
    }
};

BOOST_FIXTURE_TEST_SUITE(sodium_test_suite, SodiumFixture)

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_full)
{
    auto r1{ sodium::randombytes_buf(100) };

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(!sodium::is_zero(r1));

    // expect something like
    // class std::vector<unsigned char, class std::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_empty)
{
    auto r1{ sodium::randombytes_buf(0) };

    BOOST_CHECK(r1.size() == 0);
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_full_bytes_protected)
{
    auto r1{ sodium::randombytes_buf<sodium::bytes_protected>(100) };

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(!sodium::is_zero(r1));

    // expect something like
    // class std::vector<unsigned char, class sodium::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_inplace_full)
{
    sodium::bytes r1(100);
    BOOST_CHECK(sodium::is_zero(r1));

    sodium::randombytes_buf_inplace(r1);

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(!sodium::is_zero(r1));

    // expect something like
    // class std::vector<unsigned char, class std::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_inplace_empty)
{
    sodium::bytes r1; // empty

    sodium::randombytes_buf_inplace(r1);

    BOOST_CHECK(r1.size() == 0);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_random_randombytes_buf_inplace_full_bytes_protected)
{
    sodium::bytes_protected r1(100);
    BOOST_CHECK(sodium::is_zero(r1));

    // selects sodium::randombytes_buf_inplace<sodium::bytes_protected>()
    sodium::randombytes_buf_inplace(r1);

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(!sodium::is_zero(r1));

    // expect something like
    // class std::vector<unsigned char, class sodium::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_inplace_full_array)
{
    std::array<sodium::byte, 100> r1{ 0 };

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(sodium::is_zero(r1));

    // selects sodium::randombytes_buf_inplace<std::array<sodium::byte, 100>>()
    sodium::randombytes_buf_inplace(r1);

    BOOST_CHECK(r1.size() == 100);
    BOOST_CHECK(!sodium::is_zero(r1));

    // expect something lise
    // class std::array<unsigned char, 100>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(sodium_test_random_randombytes_buf_different_each_time)
{
    auto r1{ sodium::randombytes_buf(100) };
    auto r2{ sodium::randombytes_buf(100) };

    // the bigger the buffers, the more negligible
    // the probability to get identical random values.
    // In this case, we can fail this test with
    // negligible probability.
    BOOST_CHECK(sodium::compare(r1, r2) == false);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_random_randombytes_buf_deterministic_full_same_seeds)
{
    sodium::default_seed_type s1{ sodium::randombytes_keygen() };

    auto r1{ sodium::randombytes_buf_deterministic(100, s1) };
    auto r2{ sodium::randombytes_buf_deterministic(100, s1) };

    BOOST_CHECK(!sodium::is_zero(r1));
    BOOST_CHECK(!sodium::is_zero(r2));

    // same seeds means same random buffers
    BOOST_CHECK(sodium::compare(r1, r2) == true);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_random_randombytes_buf_deterministic_full_different_seeds)
{
    sodium::default_seed_type s1{ sodium::randombytes_keygen() };
    sodium::default_seed_type s2{ sodium::randombytes_keygen() };

    // both seeds should be different
    BOOST_CHECK(sodium::compare(s1, s2) == false);

    auto r1{ sodium::randombytes_buf_deterministic(100, s1) };
    auto r2{ sodium::randombytes_buf_deterministic(100, s2) };

    BOOST_CHECK(!sodium::is_zero(r1));
    BOOST_CHECK(!sodium::is_zero(r2));

    // different seeds means different random buffers
    BOOST_CHECK(sodium::compare(r1, r2) == false);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_random_randombytes_buf_deterministic_full_bytes_protected_same_seeds)
{
    sodium::default_seed_type s1{ sodium::randombytes_keygen() };

    auto r1{ sodium::randombytes_buf_deterministic<sodium::bytes_protected>(
      100, s1) };
    auto r2{ sodium::randombytes_buf_deterministic<sodium::bytes_protected>(
      100, s1) };

    BOOST_CHECK(!sodium::is_zero(r1));
    BOOST_CHECK(!sodium::is_zero(r2));

    // same seeds means same random buffers
    BOOST_CHECK(sodium::compare(r1, r2) == true);

    // expect something like
    // class std::vector<unsigned char, class sodium::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

BOOST_AUTO_TEST_CASE(
  sodium_test_random_randombytes_buf_deterministic_full_bytes_protected_different_seeds)
{
    sodium::default_seed_type s1{ sodium::randombytes_keygen() };
    sodium::default_seed_type s2{ sodium::randombytes_keygen() };

    // both seeds should be different
    BOOST_CHECK(sodium::compare(s1, s2) == false);

    auto r1{ sodium::randombytes_buf_deterministic<sodium::bytes_protected>(
      100, s1) };
    auto r2{ sodium::randombytes_buf_deterministic<sodium::bytes_protected>(
      100, s2) };

    BOOST_CHECK(!sodium::is_zero(r1));
    BOOST_CHECK(!sodium::is_zero(r2));

    // different seeds means different random buffers
    BOOST_CHECK(sodium::compare(r1, r2) == false);

    // expect something like
    // class std::vector<unsigned char, class sodium::allocator<unsigned char>>
    BOOST_TEST_MESSAGE(typeid(r1).name());
}

// XXX add missing tests.

BOOST_AUTO_TEST_SUITE_END()
