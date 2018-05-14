// test_helpers.cpp -- Test universal helpers
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
//    ./test_helpers --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::helpers Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "helpers.h"
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <sstream>
#include <algorithm>

constexpr int TEST_COUNT_COMPARE = 50000000;
constexpr int TEST_COUNT_IS_ZERO = 5000;

struct SodiumFixture {
	SodiumFixture() {
		BOOST_REQUIRE(sodium_init() != -1);
		// BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
	}
	~SodiumFixture() {
		// BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
	}
};

BOOST_FIXTURE_TEST_SUITE(sodium_test_suite, SodiumFixture)

bool is_zero_naive(const sodium::bytes &v)
{
	// DON'T do this in crypto code: time-dependent on input v.
	// Use constant-time sodium::is_zero() instead.

	return std::find_if(v.cbegin(), v.cend(),
		[](sodium::byte b) { return b != 0; }) == v.cend();
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_compare_equal)
{
	std::string s{ "0123456789abced" };
	sodium::bytes b1(s.cbegin(), s.cend());
	sodium::bytes b2(b1); // a copy

	// selects sodium::compare<bytes>():
	bool result = sodium::compare(b1, b2);

	BOOST_CHECK(result == true);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_compare_unequal)
{
	std::string s{ "0123456789abced" };
	sodium::bytes b1(s.cbegin(), s.cend());
	sodium::bytes b2(b1); // a copy
	++b2[8]; // change it

	bool result = sodium::compare(b1, b2);

	BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_compare_unequal_sizes)
{
	std::string s{ "0123456789abced" };
	sodium::bytes b1(s.cbegin(), s.cend());
	sodium::bytes b2; // empty
	bool result = false;

	try {
		result = sodium::compare(b1, b2);
	}
	catch (std::runtime_error &e) {
		BOOST_TEST_MESSAGE("b1, b2 different sizes, as expected");
		result = false;
	}

	BOOST_CHECK(result == false);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_compare_equal_chars)
{
	std::string s{ "0123456789abced" };
	sodium::chars b1(s.cbegin(), s.cend());
	sodium::chars b2(b1); // a copy

	// selects sodium::compare<chars>():
	bool result = sodium::compare(b1, b2);

	BOOST_CHECK(result == true);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_classic_compare_timing)
{
	std::string s{ "0123456789abced" };
	sodium::bytes b1(s.cbegin(), s.cend());
	sodium::bytes b2(b1); // a copy
	++b2[8]; // change it in the middle

	// time lexicographic comparison of equal bytes
	auto t0 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_COMPARE; ++i)
		static_cast<void>(std::memcmp(b1.data(), b1.data(), b1.size()));
	auto t1 = std::chrono::system_clock::now();
	auto time_classic_compare_equal = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

	// time lexicographic comparison of unequal bytes
	auto t2 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_COMPARE; ++i)
		static_cast<void>(std::memcmp(b1.data(), b2.data(), b1.size()));
	auto t3 = std::chrono::system_clock::now();
	auto time_classic_compare_unequal = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2);

	// we expect the first comparison to take significantly
	// more time than the second comparison.

	std::ostringstream oss;
	oss << "classical compare b1==b1: "
		<< time_classic_compare_equal.count()
		<< " milliseconds." << "\n";
	oss << "classical compare b1!=b2: "
		<< time_classic_compare_unequal.count()
		<< " milliseconds.";
	BOOST_TEST_MESSAGE(oss.str());
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_sodium_compare_timing)
{
	std::string s{ "0123456789abced" };
	sodium::bytes b1(s.cbegin(), s.cend());
	sodium::bytes b2(b1); // a copy
	++b2[8]; // change it in the middle

	// time constant-time comparison of equal bytes
	auto t0 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_COMPARE; ++i)
		static_cast<void>(sodium::compare(b1, b1));
	auto t1 = std::chrono::system_clock::now();
	auto time_sodium_compare_equal = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

	// time constant-time comparison of unequal bytes
	auto t2 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_COMPARE; ++i)
		static_cast<void>(sodium::compare(b1, b2));
	auto t3 = std::chrono::system_clock::now();
	auto time_sodium_compare_unequal = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2);

	// we expect both comparisons to take approximately
	// the same time (constant-time comparison)

	std::ostringstream oss;
	oss << "sodium compare b1==b1: "
		<< time_sodium_compare_equal.count()
		<< " milliseconds." << "\n";
	oss << "sodium compare b1!=b2: "
		<< time_sodium_compare_unequal.count()
		<< " milliseconds.";
	BOOST_TEST_MESSAGE(oss.str());
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_sodium_is_zero)
{
	sodium::bytes b1(100000); // so many 0 bytes
	sodium::bytes b2(b1);     // a copy
	++b2[50000];              // change it in the middle

	bool result_b1 = sodium::is_zero(b1);
	bool result_b2 = sodium::is_zero(b2);

	BOOST_CHECK(result_b1 == true);
	BOOST_CHECK(result_b2 == false);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_is_zero_naive)
{
	sodium::bytes b1(100000); // so many 0 bytes
	sodium::bytes b2(b1);     // a copy
	++b2[50000];              // change it in the middle

	bool result_b1 = is_zero_naive(b1);
	bool result_b2 = is_zero_naive(b2);

	BOOST_CHECK(result_b1 == true);
	BOOST_CHECK(result_b2 == false);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_sodium_is_zero_timing_all_zeroes)
{
	sodium::bytes b(100000); // so many 0 bytes

	// time constant-time is_zero()
	auto t0 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_IS_ZERO; ++i)
		static_cast<void>(sodium::is_zero(b));
	auto t1 = std::chrono::system_clock::now();
	auto time_sodium_is_zero_true = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

	// time regular comparison with 0
	auto t2 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_IS_ZERO; ++i)
		static_cast<void>(is_zero_naive(b));
	auto t3 = std::chrono::system_clock::now();
	auto time_is_zero_naive_true = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2);

	// we expect the naive version to take approximately
	// the same time as the constant time version
	// when both inputs are all-zeroes.

	std::ostringstream oss;
	oss << "is_zero_naive(==0)   "
		<< time_is_zero_naive_true.count()
		<< " milliseconds." << "\n";
	oss << "sodium::is_zero(==0) "
		<< time_sodium_is_zero_true.count()
		<< " milliseconds.";

	BOOST_TEST_MESSAGE(oss.str());
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_sodium_is_zero_timing_not_all_zeroes)
{
	sodium::bytes b(100000); // so many 0 bytes
	++b[50000];              // change it in the middle

	// time constant-time is_zero()
	auto t0 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_IS_ZERO; ++i)
		static_cast<void>(sodium::is_zero(b));
	auto t1 = std::chrono::system_clock::now();
	auto time_sodium_is_zero_false = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);

	// time regular comparison with 0
	auto t2 = std::chrono::system_clock::now();
	for (int i = 0; i != TEST_COUNT_IS_ZERO; ++i)
		static_cast<void>(is_zero_naive(b));
	auto t3 = std::chrono::system_clock::now();
	auto time_is_zero_naive_false = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2);

	// we expect the naive version to take approximately
	// half the time of the constant time version
	// when the input differs from all-zero at the middle.

	std::ostringstream oss;
	oss << "is_zero_naive(!=0)   "
		<< time_is_zero_naive_false.count()
		<< " milliseconds." << "\n";
	oss << "sodium::is_zero(!=0) "
		<< time_sodium_is_zero_false.count()
		<< " milliseconds." << "\n";

	BOOST_TEST_MESSAGE(oss.str());
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_full)
{
	std::string in1{ "0123456789" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2hex<bytes>()
	std::string hexb1{ sodium::bin2hex(b1) };

	BOOST_CHECK(hexb1 == "30313233343536373839");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_empty)
{
	sodium::bytes b1; // empty

	std::string hexb1{ sodium::bin2hex(b1) };

	BOOST_CHECK(hexb1 == "");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_chars)
{
	std::string in1{ "0123456789" };
	sodium::chars b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2hex<chars>()
	std::string hexb1{ sodium::bin2hex(b1) };

	BOOST_CHECK(hexb1 == "30313233343536373839");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_string)
{
	std::string in1{ "0123456789" };

	// selects sodium::bin2hex<std::string>()
	std::string hexin1{ sodium::bin2hex(in1) };

	BOOST_CHECK(hexin1 == "30313233343536373839");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_string_clearmem_true)
{
	std::string in1{ "0123456789" };

	// selects sodium::bin2hex<std::string>()
	std::string hexin1{ sodium::bin2hex(in1, true) };

	BOOST_CHECK(hexin1 == "30313233343536373839");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_string_clearmem_false)
{
	std::string in1{ "0123456789" };

	// selects sodium::bin2hex<std::string>()
	std::string hexin1{ sodium::bin2hex(in1, false) };

	BOOST_CHECK(hexin1 == "30313233343536373839");
}

BOOST_AUTO_TEST_SUITE_END()
