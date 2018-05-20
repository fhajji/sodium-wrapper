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
#include "key.h"
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <type_traits>
#include <typeinfo>

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

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_return_string_protected)
{
	std::string in1{ "0123456789" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// returns a sodium::string_protected
	auto hexb1{ sodium::bin2hex<sodium::bytes, sodium::string_protected>(b1) };

	// expect something like
	// class std::basic_string<char, struct std::char_traits<char>, class sodium::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(hexb1).name());

	// since this is a sodium::string_protected,
	// let's make it read-only, just for kicks:
	
	// C++17?
	// hexb1.get_allocator().readonly(hexb1.data());

	// C++11: std::basic_string<...>.data() is <const T *>, we need <T *>:
	hexb1.get_allocator().readonly(const_cast<char *>(hexb1.data()));

	BOOST_CHECK(hexb1 == "30313233343536373839");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_return_string_protected_clearmem)
{
	std::string in1{ "0123456789" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// returns a sodium::string_protected
	auto hexb1{ sodium::bin2hex<sodium::bytes, sodium::string_protected>(b1, true) };

	// expect something like
	// class std::basic_string<char, struct std::char_traits<char>, class sodium::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(hexb1).name());

	// since this is a sodium::string_protected,
	// let's make it read-only, just for kicks:

	// C++17?
	// hexb1.get_allocator().readonly(hexb1.data());

	// C++11: std::basic_string<...>.data() is <const T *>, we need <T *>:
	hexb1.get_allocator().readonly(const_cast<char *>(hexb1.data()));

	BOOST_CHECK(hexb1 == "30313233343536373839");
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

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_key)
{
	sodium::key<sodium::KEYSIZE_SECRETBOX> some_key; // random values

	// selects sodium::bin2hex<sodium::key<>>()
	std::string hex_some_key{ sodium::bin2hex(some_key, true) };

	BOOST_TEST_MESSAGE(hex_some_key);

	BOOST_CHECK(some_key.size() == sodium::KEYSIZE_SECRETBOX);
	BOOST_CHECK(hex_some_key.size() == sodium::KEYSIZE_SECRETBOX * 2);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_key_return_string_protected_clearmem)
{
	sodium::key<sodium::KEYSIZE_SECRETBOX> some_key; // random values

	auto hex_some_key{ sodium::bin2hex<sodium::key<sodium::KEYSIZE_SECRETBOX>, sodium::string_protected>(some_key, true) };

	BOOST_TEST_MESSAGE(hex_some_key);

	// expect something like
	// class std::basic_string<char, struct std::char_traits<char>, class sodium::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(hex_some_key).name());

	BOOST_CHECK(some_key.size() == sodium::KEYSIZE_SECRETBOX);
	BOOST_CHECK(hex_some_key.size() == sodium::KEYSIZE_SECRETBOX * 2);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_full)
{
	std::string in1{ "30313233343536373839" };
	auto bin = sodium::hex2bin(in1);

	// expect something like
	// class std::vector<unsigned char, class std::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	BOOST_CHECK(bin[0] == '0');
	BOOST_CHECK(bin[1] == '1');
	BOOST_CHECK(bin[9] == '9');

	BOOST_CHECK(bin.size() == 10);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_empty)
{
	std::string in1; // empty
	auto bin = sodium::hex2bin(in1);

	BOOST_CHECK(bin.size() == 0);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_chars)
{
	std::string in1{ "30313233343536373839" };
	auto bin = sodium::hex2bin<sodium::chars>(in1);

	// expect something like
	// class std::vector<char, class std::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	BOOST_CHECK(bin[0] == '0');
	BOOST_CHECK(bin[1] == '1');
	BOOST_CHECK(bin[9] == '9');

	BOOST_CHECK(bin.size() == 10);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_bytes_protected)
{
	std::string in1{ "30313233343536373839" };
	auto bin = sodium::hex2bin<sodium::bytes_protected>(in1);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	BOOST_CHECK(bin[0] == '0');
	BOOST_CHECK(bin[1] == '1');
	BOOST_CHECK(bin[9] == '9');

	BOOST_CHECK(bin.size() == 10);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_ignore1)
{
	std::string in1{ "30:31:32:33:34:35:36:37:38:39" };
	auto bin = sodium::hex2bin(in1, ":");

	BOOST_CHECK(bin[0] == '0');
	BOOST_CHECK(bin[1] == '1');
	BOOST_CHECK(bin[9] == '9');

	BOOST_CHECK(bin.size() == 10);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_hex2bin_ignore2)
{
	std::string in1{ "30:31:32:33:34:35:36:37:38:39" };
	auto bin = sodium::hex2bin(in1 /*, without specifying ":" */);

	BOOST_CHECK(bin[0] == '0');

	// parsing stops at first non-ignored, non-hex char in input
	BOOST_CHECK(bin.size() == 1);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes>()
	std::string base64b1{ sodium::bin2base64(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_empty)
{
	sodium::bytes b1; // empty

					  // selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes>()
	std::string base64b1{ sodium::bin2base64(b1) };

	BOOST_CHECK(base64b1.size() == 0);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_return_string_protected)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	auto base64b1{ sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes, sodium::string_protected>(b1) };

	// expect something like
	// class std::basic_string<char, struct std::char_traits<char>, class sodium::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(base64b1).name());

	// since this is a sodium::string_protected,
	// let's make it read-only, just for kicks:

	// C++17?
	// hexb1.get_allocator().readonly(base64b1.data());

	// C++11: std::basic_string<...>.data() is <const T *>, we need <T *>:
	base64b1.get_allocator().readonly(const_cast<char *>(base64b1.data()));

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_return_string_protected_clearmem)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	auto base64b1{ sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes, sodium::string_protected>(b1,true) };

	// expect something like
	// class std::basic_string<char, struct std::char_traits<char>, class sodium::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(base64b1).name());

	// since this is a sodium::string_protected,
	// let's make it read-only, just for kicks:

	// C++17?
	// hexb1.get_allocator().readonly(base64b1.data());

	// C++11: std::basic_string<...>.data() is <const T *>, we need <T *>:
	base64b1.get_allocator().readonly(const_cast<char *>(base64b1.data()));

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}


BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_chars)
{
	std::string in1{ "subjects?_d" };
	sodium::chars b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::chars>()
	std::string base64b1{ sodium::bin2base64(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_string)
{
	std::string in1{ "subjects?_d" };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, std::string>()
	std::string base64b1{ sodium::bin2base64(in1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_bytes_protected)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes_protected b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes_protected>()
	std::string base64b1{ sodium::bin2base64(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_bytes_protected_clearmem)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes_protected b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes_protected>(BT, bool)
	std::string base64b1{ sodium::bin2base64(b1, true) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_key)
{
	sodium::key<sodium::KEYSIZE_SECRETBOX> some_key; // random

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::key<sodium::KEYSIZE_SECRETBOX>()
	// CAREFUL: temp buffer allocated on the heap with key material in base64 NOT zeroed.
	std::string base64b1{ sodium::bin2base64(some_key) };

	BOOST_TEST_MESSAGE(base64b1);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_key_clearmem)
{
	sodium::key<sodium::KEYSIZE_SECRETBOX> some_key; // random

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::key<sodium::KEYSIZE_SECRETBOX>(BT, bool)
	// CAREFUL: though the temp buffer on the heap with key material in base64 is zeroed,
	// it was accessible for a small time window.
	std::string base64b1{ sodium::bin2base64(some_key, true) };

	BOOST_TEST_MESSAGE(base64b1);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_nopadding)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL_NO_PADDING, sodium::bytes>
	std::string base64b1{ sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL_NO_PADDING>(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_urlsafe)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_URLSAFE, sodium::bytes>
	std::string base64b1{ sodium::bin2base64<sodium_base64_VARIANT_URLSAFE>(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM_X2Q=");
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_full_urlsafe_nopadding)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// selects sodium::bin2base64<sodium_base64_VARIANT_URLSAFE_NO_PADDING, sodium::bytes>
	std::string base64b1{ sodium::bin2base64<sodium_base64_VARIANT_URLSAFE_NO_PADDING>(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM_X2Q");
}

// ------------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_full)
{
	std::string in1{ "c3ViamVjdHM/X2Q=" };
	
	// selects sodium::base642bin<sodium_base64_VARIANT_ORIGINAL, std::string, sodium::bytes>()
	auto bin = sodium::base642bin(in1);

	// expect something like
	// class std::vector<unsigned char, class std::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_empty)
{
	std::string in1; // empty

	// selects sodium::base642bin<sodium_base64_VARIANT_ORIGINAL, std::string, sodium::bytes>()
	auto bin = sodium::base642bin(in1);

	BOOST_CHECK(bin.size() == 0);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_chars)
{
	std::string in1{ "c3ViamVjdHM/X2Q=" };
	
	auto bin = sodium::base642bin<sodium_base64_VARIANT_ORIGINAL, std::string, sodium::chars>(in1);

	// expect something like
	// class std::vector<char, class std::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::chars result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_bytes_protected)
{
	std::string in1{ "c3ViamVjdHM/X2Q=" };

	// note: this combination makes little practical sense.
	// if we are going to return protected memory, we should
	// as well have had the input in protectes string. But,
	// this is merely a test case.
	auto bin = sodium::base642bin<sodium_base64_VARIANT_ORIGINAL, std::string, sodium::bytes_protected>(in1);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes_protected result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_string_protected_bytes_protected)
{
	// well, the literal string still ain't protected, but anyway...
	sodium::string_protected in1{ "c3ViamVjdHM/X2Q=" };

	auto bin = sodium::base642bin<sodium_base64_VARIANT_ORIGINAL, sodium::string_protected, sodium::bytes_protected>(in1);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	sodium::string_protected result_as_string{ "subjects?_d" };
	sodium::bytes_protected result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_ignore1)
{
	std::string in1{ "c3:Vi:am:Vj:dH::M/X2:Q=" };
	auto bin = sodium::base642bin(in1, ":");

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_ignore2)
{
	std::string in1{ "c3:Vi:am:Vj:dH::M/X2:Q=" };

	try {
		auto bin = sodium::base642bin(in1 /*, without specifying ":" */);
		// we shouldn'n make it here:
		BOOST_CHECK(false);
	}
	catch (std::runtime_error &e) {
		// indeed, this is a misformed base64 input
		BOOST_TEST_MESSAGE("caught EXPECTED base64 decoding failure");
	}

	// parsing stops at first non-ignored, non-hex char in input.
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_full_variant2)
{
	std::string in1{ "c3ViamVjdHM/X2Q" };

	// selects sodium::base642bin<sodium_base64_VARIANT_ORIGINAL_NO_PADDING, std::string, sodium::bytes>()
	auto bin = sodium::base642bin<sodium_base64_VARIANT_ORIGINAL_NO_PADDING>(in1);

	// expect something like
	// class std::vector<unsigned char, class std::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_full_variant3)
{
	std::string in1{ "c3ViamVjdHM_X2Q=" };

	// selects sodium::base642bin<sodium_base64_VARIANT_URLSAFE, std::string, sodium::bytes>()
	auto bin = sodium::base642bin<sodium_base64_VARIANT_URLSAFE>(in1);

	// expect something like
	// class std::vector<unsigned char, class std::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

BOOST_AUTO_TEST_CASE(sodium_test_helpers_base642bin_full_variant4)
{
	std::string in1{ "c3ViamVjdHM_X2Q" };

	// selects sodium::base642bin<sodium_base64_VARIANT_URLSAFE_NO_PADDING, std::string, sodium::bytes>()
	auto bin = sodium::base642bin<sodium_base64_VARIANT_URLSAFE_NO_PADDING>(in1);

	// expect something like
	// class std::vector<unsigned char, class std::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(bin).name());

	std::string result_as_string{ "subjects?_d" };
	sodium::bytes result{ result_as_string.cbegin(), result_as_string.cend() };
	BOOST_CHECK(bin == result);
}

// ------------------------------------------------------------------------------

// The following test cases are commented out, because they
// are not supposed to compile. Uncomment to test template
// argument verification.

#if 0
BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2hex_wrong_return_type)
{
	std::string in1{ "0123456789" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// should not compile, because std::wstring is wrong return type
	auto hexb1{ sodium::bin2hex<sodium::bytes, std::wstring>(b1) };

	BOOST_CHECK(hexb1 == "30313233343536373839");
}
#endif

#if 0
BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_wrong_variant)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// should not compile, because 666 is wrong variant
	std::string base64b1{ sodium::bin2base64<666, sodium::bytes>(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}
#endif

#if 0
BOOST_AUTO_TEST_CASE(sodium_test_helpers_bin2base64_wrong_return_type)
{
	std::string in1{ "subjects?_d" };
	sodium::bytes b1{ in1.cbegin(), in1.cend() };

	// should not compile, because std::wstring is wrong return type
	std::string base64b1{ sodium::bin2base64<sodium_base64_VARIANT_ORIGINAL, sodium::bytes, std::wstring>(b1) };

	BOOST_CHECK(base64b1 == "c3ViamVjdHM/X2Q=");
}
#endif

BOOST_AUTO_TEST_SUITE_END()
