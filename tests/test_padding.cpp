// test_padding.cpp -- Test padding functions
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
//    ./test_padding --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::padding Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "padding.h"
#include <vector>
#include <string>
#include <typeinfo>

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

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_full)
{
	std::string s{ "0123456789abcde" }; // shorter than blocksize
	sodium::bytes b1(s.cbegin(), s.cend());

	// selects sodium::pad<bytes>():
	auto padded = sodium::pad(b1, 16);

	// original buffer was left untouched
	BOOST_CHECK(b1.size() == 15);

	// new buffer is at full multiple of blocksize length
	BOOST_CHECK(padded.size() == 16);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_full_already_blocksize)
{
	std::string s{ "0123456789abcdef" }; // already at blocksize
	sodium::bytes b1(s.cbegin(), s.cend());

	// selects sodium::pad<bytes>():
	auto padded = sodium::pad(b1, 16);

	// new size didn't change (we didn't touch b1)
	BOOST_CHECK(b1.size() == 16);

	// new padded size as returned is exactly one addional block more
	BOOST_CHECK(padded.size() == 16 + 16); // original size + one full additional block
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_empty)
{
	sodium::bytes b1; // empty

	// selects sodium::pad<bytes>():
	auto padded = sodium::pad(b1, 16);

	// original buffer was left untouched
	BOOST_CHECK(b1.size() == 0);

	// new buffer is at full multiple of blocksize length
	BOOST_CHECK(padded.size() == 16); // at least one more block
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_full_protected_bytes)
{
	// literal string is still not protected,
	// but we don't care
	sodium::string_protected s{ "0123456789abcde" }; // shorter than blocksize
	sodium::bytes_protected b1(s.cbegin(), s.cend());

	// selects sodium::pad<sodium::bytes_protected>():
	auto padded = sodium::pad(b1, 16);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(padded).name());

	// original buffer was left untouched
	BOOST_CHECK(b1.size() == 15);

	// new buffer is at full multiple of blocksize length
	BOOST_CHECK(padded.size() == 16);

	// XXX NOTE: with the current (lazy) implementation of sodium::pad(),
	// we can observe in debug mode:
	//   sodium::allocate(15)   /// for s OR b1 (one elided by compiler?)
	//   sodium::allocate(31)   /// inside sodium::pad() (one blocksize more)
	// This is suboptimal -- needs fixing.
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_full_inplace)
{
	std::string s{ "0123456789abcde" }; // shorter than blocksize
	sodium::bytes b1(s.cbegin(), s.cend());

	// selects sodium::pad_inplace<bytes>():
	sodium::pad_inplace(b1, 16);

	// new size is multiple of blocksize
	BOOST_CHECK(b1.size() == 16);

	// original data was not changed
	for (int i = 0; i != 15; ++i)
		BOOST_CHECK(b1[i] == static_cast<unsigned char>(s[i]));
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_empty_inplace)
{
	sodium::bytes b1; // empty

	// selects sodium::pad_inplace<bytes>():
	sodium::pad_inplace(b1, 16);

	// new size is multiple of blocksize
	BOOST_CHECK(b1.size() == 16); // but at least one block
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_pad_full_inplace_already_blocksize)
{
	std::string s{ "0123456789abcdef" }; // already at blocksize
	sodium::bytes b1(s.cbegin(), s.cend());

	// selects sodium::pad_inplace<bytes>():
	sodium::pad_inplace(b1, 16);

	// original size, plus one full additional block
	BOOST_CHECK(b1.size() == 16 + 16);

	// original data was not changed
	for (int i = 0; i != 16; ++i)
		BOOST_CHECK(b1[i] == static_cast<unsigned char>(s[i]));
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_full)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	auto unpadded = sodium::unpad(padded, 16);

	BOOST_CHECK(unpadded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_already_blocksize)
{
	std::string in_as_string{ "0123456789abcdef" }; // a multiple of bloksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	auto unpadded = sodium::unpad(padded, 16);

	BOOST_CHECK(unpadded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_empty)
{
	sodium::bytes in; // empty, has no pad

	auto padded = sodium::pad(in, 16);
	auto unpadded = sodium::unpad(padded, 16);

	BOOST_CHECK(unpadded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_full_original_unmodified)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	auto padded_copy{ padded };

	auto unpadded = sodium::unpad(padded, 16);

	BOOST_CHECK(unpadded == in);
	BOOST_CHECK(padded == padded_copy); // sodium::unpad() didn't change input
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_full_chars)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::chars in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);

	// selects sodium::unpad<sodium::chars>(...)
	auto unpadded = sodium::unpad(padded, 16);

	// expect something like
	// class std::vector<char, class std::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(unpadded).name());

	BOOST_CHECK(unpadded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_full_bytes_protected)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes_protected in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);

	// selects sodium::unpad<sodium::bytes_protected>(...)
	auto unpadded = sodium::unpad(padded, 16);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(unpadded).name());

	BOOST_CHECK(unpadded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_tamper_with_pad)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	++(*padded.rbegin()); // change last byte of pad

	try {
		auto unpadded = sodium::unpad(padded, 16);

		// we shouldn't reach this
		BOOST_CHECK(false); // failed test
	}
	catch (std::runtime_error &e) {
		BOOST_TEST_MESSAGE("sodium::unpad() detected pad tampering, as expected");
	}
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_full)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	sodium::unpad_inplace(padded, 16);

	BOOST_CHECK(padded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_already_blocksize)
{
	std::string in_as_string{ "0123456789abcdef" }; // a multiple of bloksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	sodium::unpad_inplace(padded, 16);

	BOOST_CHECK(padded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_empty)
{
	sodium::bytes in; // empty, has no pad

	auto padded = sodium::pad(in, 16);
	sodium::unpad_inplace(padded, 16);

	BOOST_CHECK(padded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_full_chars)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::chars in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);

	// selects sodium::unpad_inplace<sodium::chars>(...)
	sodium::unpad_inplace(padded, 16);

	// expect something like
	// class std::vector<char, class std::allocator<char>>
	BOOST_TEST_MESSAGE(typeid(padded).name());

	BOOST_CHECK(padded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_full_bytes_protected)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes_protected in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);

	// selects sodium::unpad_inplace<sodium::bytes_protected>(...)
	sodium::unpad_inplace(padded, 16);

	// expect something like
	// class std::vector<unsigned char, class sodium::allocator<unsigned char>>
	BOOST_TEST_MESSAGE(typeid(padded).name());

	BOOST_CHECK(padded == in);
}

BOOST_AUTO_TEST_CASE(sodium_test_padding_unpad_inplace_tamper_with_pad)
{
	std::string in_as_string{ "0123456789abcde" }; // smaller than blocksize
	sodium::bytes in{ in_as_string.cbegin(), in_as_string.cend() };

	auto padded = sodium::pad(in, 16);
	++(*padded.rbegin()); // change last byte of pad

	try {
		sodium::unpad_inplace(padded, 16);

		// we shouldn't reach this
		BOOST_CHECK(false); // failed test
	}
	catch (std::runtime_error &e) {
		BOOST_TEST_MESSAGE("sodium::unpad_inplace() detected pad tampering, as expected");
	}
}

BOOST_AUTO_TEST_SUITE_END()
