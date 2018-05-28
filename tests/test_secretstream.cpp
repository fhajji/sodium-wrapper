// test_secretstream.cpp -- Test sodium::secretstream
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

// To see test messages, including timing results:
//    ./test_secretstream --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::secretstream Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "key.h"
#include "secretstream.h"
#include <sodium.h>
#include <string>
#include <stdexcept>
#include <utility>

template <typename BT>
BT
s2b(const std::string &s)
{
	BT vec{ s.cbegin(), s.cend() };
	return vec;
}

template <typename BT>
BT
s2b(void)
{
	BT vec;
	return vec; // empty vector
}

template <typename BT=sodium::bytes>
bool
test_of_correctness(bool falsify_ciphertext=false,
	bool falsify_added_data=false,
	bool falsify_header=false,
	bool falsify_order=false,
	bool falsify_skip_message=false,
	bool falsify_skip_last_message=false,
	bool test_rekey_out_of_band=false,
	bool test_rekey_in_band=false)
{
	std::vector<BT> m{ s2b<BT>("m0"), s2b<BT>("m#1"), s2b<BT>(), s2b<BT>("m3") }; // plaintexts
	std::vector<BT> a{ s2b<BT>("a0"), s2b<BT>(), s2b<BT>("a#2"), s2b<BT>("a3") }; // added data
	std::vector<BT> c; // ciphertexts with MAC
	BT m_dec; // decrypted ciphertext

	auto tag_message{ sodium::secretstream<BT>::tag_message() };
	auto tag_final{ sodium::secretstream<BT>::tag_final() };
	auto tag_rekey{ sodium::secretstream<BT>::tag_rekey() };

	sodium::secretstream<BT>::key_type key; // random secret key

	// 1. encrypt stream

	sodium::secretstream<BT> se{ key }; // an encrypting stream
	BT header = se.init_push();

	for (int i = 0; i != m.size(); ++i) {
		if (test_rekey_out_of_band && i == 2) {
			se.rekey();
			BOOST_TEST_MESSAGE("sender: rekey(out-of-band) done");
		}

		auto tag = (test_rekey_in_band && i==2) ? tag_rekey : tag_message;

		c.push_back(se.push(m[i], a[i],
			(i == m.size() - 1 ? tag_final : tag)));

		if (test_rekey_in_band && i == 2)
			BOOST_TEST_MESSAGE("sender: rekey(in-band) sent");
	}

	// 2. falsify stuff when needed
	if (falsify_ciphertext)
		++(c[0].data()[0]);
	if (falsify_added_data)
		++(a[0].data()[0]);
	if (falsify_header)
		++(header.data()[0]);
	if (falsify_order) {
		std::swap(c[0], c[1]); // swap 1st and 2nd message
		std::swap(a[0], a[1]); // keep c and a in sync
		std::swap(m[0], m[1]); // keep c and m in sync
	}
	if (falsify_skip_message) {
		c.erase(c.begin() + 1); // remove 2nd message
		a.erase(a.begin() + 1); // keep c and a in sync
		m.erase(m.begin() + 1); // keep c and m in sync
	}
	if (falsify_skip_last_message) {
		c.pop_back(); // remove last message (w/ TAG_FINAL)
		a.pop_back(); // keep c and a in sync
		m.pop_back(); // keep c and m in sync
	}

	// 3. decrypt stream

	sodium::secretstream<BT> sd{ key }; // a decryption stream w/ same key

	int i = 0;
	try {
		sd.init_pull(header);

		auto tag{ sodium::secretstream<BT>::tag_message() };

		for (i = 0; i != c.size(); ++i) {
			if (test_rekey_out_of_band && i == 2) {
				sd.rekey();
				BOOST_TEST_MESSAGE("receiver: rekey(out-of-band) done");
			}

			m_dec = sd.pull(c[i], a[i], tag);

			BOOST_TEST(m_dec == m[i]);

			if (tag == tag_rekey)
				BOOST_TEST_MESSAGE("receiver: rekey(in-band) tag received");

			if (tag == tag_final)
				break; // that was the last message
		}
	}
	catch (std::runtime_error &e) {
		BOOST_TEST_MESSAGE(e.what());
		
		// if decryption failed, and one of the falsify_
		// flags was set, then it was expected and the
		// test _succeeded_. if no flags were set, the
		// test failed.
		return falsify_ciphertext
			|| falsify_added_data
			|| falsify_header
			|| falsify_order
			|| falsify_skip_message;
	}

	if ((i+1 != c.size()) && falsify_skip_last_message) {
		BOOST_TEST_MESSAGE("Program detected missing TAG_FINAL (as expected)");
		return true;
	}

	BOOST_TEST(i+1 == c.size()); // or we missed some messages

	return true;
}

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

// 1: sodium::bytes ----------------------------------------------

BOOST_AUTO_TEST_CASE( sodium_secretstream_test_no_falsification_bytes )
{
	BOOST_TEST(test_of_correctness<>());
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_ciphertext_bytes)
{
	BOOST_TEST(test_of_correctness<>(true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_added_data_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_header_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_order_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_skip_message_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_skip_last_message_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_rekey_out_of_band_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_rekey_in_band_bytes)
{
	BOOST_TEST(test_of_correctness<>(false, false, false, false, false, false, false, true));
}

// 2: sodium::byte_protected ------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_no_falsification_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>());
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_ciphertext_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_added_data_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_header_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_order_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_skip_message_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_skip_last_message_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_test_rekey_out_of_band_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, false, false, false, false, true));
}

BOOST_AUTO_TEST_CASE(sodium_secretstream_test_falsify_test_rekey_in_band_bytes_protected)
{
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(false, false, false, false, false, false, false, true));
}

// XXX TODO: Test that other types for F are being rejected at compile-time.

BOOST_AUTO_TEST_SUITE_END()
