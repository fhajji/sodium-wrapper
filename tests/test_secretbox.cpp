// test_secretbox.cpp -- Test sodium::secretbox
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
#define BOOST_TEST_MODULE sodium::secretbox Test
#include <boost/test/included/unit_test.hpp>

#include "secretbox.h"
#include <string>
#include <sstream>
#include <chrono>
#include <typeinfo>
#include <sodium.h>

using namespace std::chrono;

using sodium::secretbox;
using bytes = sodium::bytes;

// XXX TODO templatize test functions on bytes type...

bool
test_of_correctness(const std::string &plaintext,
		    bool falsify_ciphertext=false,
		    bool falsify_mac=false,
		    bool falsify_key=false,
		    bool falsify_nonce=false)
{
  secretbox<>::key_type   key;
  secretbox<>::key_type   key2;
  secretbox<>::nonce_type nonce {};
  secretbox<>::nonce_type nonce2 {};

  secretbox<> sc{ std::move(key) };
  secretbox<> sc2{ std::move(key2) };

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() == secretbox<>::MACSIZE + plainblob.size());
  
  if (! plaintext.empty() && falsify_ciphertext) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[secretbox<>::MACSIZE]; // falsify ciphertext
  }
  
  if (falsify_mac) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[0]; // falsify MAC
  }

  try {
	bytes decrypted = (falsify_key ? sc2 : sc).decrypt(ciphertext, (falsify_nonce ? nonce2 : nonce));
	
    BOOST_CHECK(decrypted.size()  == plainblob.size());

    // decryption succeeded and plainblob == decrypted if and only if
    // we didn't falsify the ciphertext nor the MAC nor the key nor the nonce
    
    return !falsify_ciphertext &&
      !falsify_mac &&
      !falsify_key &&
      !falsify_nonce &&
      (plainblob == decrypted);
  }
  catch (std::exception & /* e */) {
    // decryption failed. This is expected if and only if we falsified
    // the ciphertext OR we falsified the MAC
    // OR we falsified the key
    // OR we falsified the nonce

    return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
  }

  // NOTREACHED (hopefully)
  return false;
}

bool
test_of_correctness_inplace(const std::string &plaintext,
	bool falsify_ciphertext = false,
	bool falsify_mac = false,
	bool falsify_key = false,
	bool falsify_nonce = false)
{
	secretbox<>::key_type   key;
	secretbox<>::key_type   key2;
	secretbox<>::nonce_type nonce{};
	secretbox<>::nonce_type nonce2{};

	secretbox<> sc{ std::move(key) };
	secretbox<> sc2{ std::move(key2) };

	bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

	bytes ciphertext(plainblob.size() + secretbox<>::MACSIZE);
	sc.encrypt(ciphertext, plainblob, nonce);

	BOOST_CHECK(ciphertext.size() == secretbox<>::MACSIZE + plainblob.size());

	if (!plaintext.empty() && falsify_ciphertext) {
		// ciphertext is of the form: (MAC || actual_ciphertext)
		++ciphertext[secretbox<>::MACSIZE]; // falsify ciphertext
	}

	if (falsify_mac) {
		// ciphertext is of the form: (MAC || actual_ciphertext)
		++ciphertext[0]; // falsify MAC
	}

	try {
		bytes decrypted(plainblob.size());

		if (falsify_key)
			sc2.decrypt(decrypted, ciphertext, 
				falsify_nonce ? nonce2 : nonce);
		else
			sc.decrypt(decrypted, ciphertext,
				falsify_nonce ? nonce2 : nonce);

		BOOST_CHECK(decrypted.size() == plainblob.size());

		// decryption succeeded and plainblob == decrypted if and only if
		// we didn't falsify the ciphertext nor the MAC nor the key nor the nonce

		return !falsify_ciphertext &&
			!falsify_mac &&
			!falsify_key &&
			!falsify_nonce &&
			(plainblob == decrypted);
	}
	catch (std::exception & /* e */) {
		// decryption failed. This is expected if and only if we falsified
		// the ciphertext OR we falsified the MAC
		// OR we falsified the key
		// OR we falsified the nonce

		return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
	}

	// NOTREACHED (hopefully)
	return false;
}

bool
test_of_correctness_detached(const std::string &plaintext,
			     bool falsify_ciphertext=false,
			     bool falsify_mac=false,
			     bool falsify_key=false,
			     bool falsify_nonce=false)
{
  secretbox<> sc;  // with random key
  secretbox<> sc2; // with (another) random key
  secretbox<>::nonce_type nonce {};
  secretbox<>::nonce_type nonce2 {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  secretbox<>::bytes_type mac(secretbox<>::MACSIZE);

  // encrypt, using detached form
  bytes ciphertext = sc.encrypt(plainblob, nonce, mac);

  BOOST_CHECK(ciphertext.size() == plainblob.size());
  
  if (! plaintext.empty() && falsify_ciphertext)
    ++ciphertext[0]; // falsify ciphertext

  if (falsify_mac)
    ++mac[0]; // falsify MAC

  try {
	  bytes decrypted = (falsify_key ? sc2 : sc).decrypt(
		  ciphertext,
		  (falsify_nonce ? nonce2 : nonce),
		  mac
	);

    BOOST_CHECK(decrypted.size()  == plainblob.size());

    // decryption succeeded and plainblob == decrypted if and only if
    // we didn't falsify the ciphertext nor the MAC nor the key nor the nonce
    
    return !falsify_ciphertext &&
      !falsify_mac &&
      !falsify_key &&
      !falsify_nonce &&
      (plainblob == decrypted);
  }
  catch (std::exception & /* e */) {
    // decryption failed. This is expected if and only if we falsified
    // the ciphertext OR we falsified the MAC
    // OR falsified the key
    // OR falsified the nonce

    return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
  }

  // NOTREACHED (hopefully)
  return false;
}

bool
test_of_correctness_detached_inplace(const std::string &plaintext,
	bool falsify_ciphertext = false,
	bool falsify_mac = false,
	bool falsify_key = false,
	bool falsify_nonce = false)
{
	secretbox<> sc;  // with random key
	secretbox<> sc2; // with (another) random key
	secretbox<>::nonce_type nonce{};
	secretbox<>::nonce_type nonce2{};

	bytes plainblob{ plaintext.cbegin(), plaintext.cend() };
	secretbox<>::bytes_type mac(secretbox<>::MACSIZE);

	// encrypt, using detached form
	bytes ciphertext(plainblob.size());
	sc.encrypt(ciphertext, plainblob, nonce, mac);

	BOOST_CHECK(ciphertext.size() == plainblob.size());

	if (!plaintext.empty() && falsify_ciphertext)
		++ciphertext[0]; // falsify ciphertext

	if (falsify_mac)
		++mac[0]; // falsify MAC

	try {
		bytes decrypted(plainblob.size());
		if (falsify_key)
			sc2.decrypt(decrypted, ciphertext, 
				falsify_nonce ? nonce2 : nonce, mac);
		else
			sc.decrypt(decrypted, ciphertext, 
				falsify_nonce ? nonce2 : nonce, mac);

		BOOST_CHECK(decrypted.size() == plainblob.size());

		// decryption succeeded and plainblob == decrypted if and only if
		// we didn't falsify the ciphertext nor the MAC nor the key nor the nonce

		return !falsify_ciphertext &&
			!falsify_mac &&
			!falsify_key &&
			!falsify_nonce &&
			(plainblob == decrypted);
	}
	catch (std::exception & /* e */) {
		// decryption failed. This is expected if and only if we falsified
		// the ciphertext OR we falsified the MAC
		// OR falsified the key
		// OR falsified the nonce

		return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
	}

	// NOTREACHED (hopefully)
	return false;
}

template <typename BT = bytes>
void
time_encrypt(const unsigned long nr_of_messages)
{
	secretbox<BT> sc;
	typename secretbox<BT>::nonce_type nonce;

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT ciphertext_with_mac_inplace(plainblob.size() + secretbox<BT>::MACSIZE);
	BT ciphertext_with_mac;

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing encrypt " << typeid(bytes_type).name() << "...\n";

	// 1. time encrypting nr_of_messages without inplace
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		ciphertext_with_mac = sc.encrypt(plainblob, nonce);
	}
	auto t01 = system_clock::now();
	auto t_no_inplace = duration_cast<milliseconds>(t01 - t00).count();

	os << "Encrypting " << nr_of_messages << " messages (no in-place): "
		<< t_no_inplace << " milliseconds." << std::endl;

	// 2. time encrypting nr_of_messages with inplace
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		sc.encrypt(ciphertext_with_mac_inplace,
			plainblob,
			nonce);
	}
	auto t11 = system_clock::now();
	auto t_inplace = duration_cast<milliseconds>(t11 - t10).count();

	os << "Encrypting " << nr_of_messages << " messages (in-place): "
		<< t_inplace << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(t_inplace < t_no_inplace,
		"sodium::secretbox::encrypt(inplace) slower than sodium::box::encrypt() ???");
}

template <typename BT = bytes>
void
time_decrypt(const unsigned long nr_of_messages)
{
	secretbox<BT> sc;
	typename secretbox<BT>::nonce_type nonce;

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT ciphertext_with_mac(plainblob.size() + secretbox<BT>::MACSIZE);

	BT decrypted_inplace(plainblob.size());
	BT decrypted;

	// we need to encrypt once (outside of timing)
	// so we have a valid ciphertext to repeatedly decrypt.
	// here, we use in-place encryption, but it doesn't
	// matter at this point.
	sc.encrypt(ciphertext_with_mac, plainblob, nonce);

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing decrypt " << typeid(bytes_type).name() << "...\n";

	// 1. time encrypting nr_of_messages without inplace
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		decrypted = sc.decrypt(ciphertext_with_mac, nonce);
	}
	auto t01 = system_clock::now();
	auto t_no_inplace = duration_cast<milliseconds>(t01 - t00).count();

	os << "Decrypting " << nr_of_messages << " messages (no in-place): "
		<< t_no_inplace << " milliseconds." << std::endl;

	// 2. time encrypting nr_of_messages with inplace
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		sc.decrypt(decrypted_inplace,
			ciphertext_with_mac,
			nonce);
	}
	auto t11 = system_clock::now();
	auto t_inplace = duration_cast<milliseconds>(t11 - t10).count();

	os << "Decrypting " << nr_of_messages << " messages (in-place): "
		<< t_inplace << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(t_inplace < t_no_inplace,
		"sodium::secretbox::decrypt(inplace) slower than sodium::box::decrypt() ???");
}

template <typename BT = bytes>
void
time_encrypt_detached(const unsigned long nr_of_messages)
{
	secretbox<BT> sc;
	typename secretbox<BT>::nonce_type nonce;

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT ciphertext_inplace(plainblob.size());
	BT ciphertext;

	BT mac(secretbox<BT>::MACSIZE);

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing encrypt detached " << typeid(bytes_type).name() << "...\n";

	// 1. time encrypting nr_of_messages without inplace
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		ciphertext = sc.encrypt(plainblob, nonce, mac);
	}
	auto t01 = system_clock::now();
	auto t_no_inplace = duration_cast<milliseconds>(t01 - t00).count();

	os << "Encrypting detached " << nr_of_messages << " messages (no in-place): "
		<< t_no_inplace << " milliseconds." << std::endl;

	// 2. time encrypting nr_of_messages with inplace
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		sc.encrypt(ciphertext_inplace,
			plainblob,
			nonce,
			mac);
	}
	auto t11 = system_clock::now();
	auto t_inplace = duration_cast<milliseconds>(t11 - t10).count();

	os << "Encrypting detached " << nr_of_messages << " messages (in-place): "
		<< t_inplace << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(t_inplace < t_no_inplace,
		"sodium::secretbox::encrypt(inplace) detached slower than sodium::box::encrypt() ???");
}

template <typename BT = bytes>
void
time_decrypt_detached(const unsigned long nr_of_messages)
{
	secretbox<BT> sc;
	typename secretbox<BT>::nonce_type nonce;

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT ciphertext(plainblob.size());

	BT mac(secretbox<BT>::MACSIZE);

	BT decrypted_inplace(plainblob.size());
	BT decrypted;

	// we need to encrypt once (outside of timing)
	// so we have a valid ciphertext to repeatedly decrypt.
	// here, we use in-place encryption, but it doesn't
	// matter at this point.
	sc.encrypt(ciphertext, plainblob, nonce, mac);

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing decrypt detached " << typeid(bytes_type).name() << "...\n";

	// 1. time encrypting nr_of_messages without inplace
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		decrypted = sc.decrypt(ciphertext, nonce, mac);
	}
	auto t01 = system_clock::now();
	auto t_no_inplace = duration_cast<milliseconds>(t01 - t00).count();

	os << "Decrypting detached " << nr_of_messages << " messages (no in-place): "
		<< t_no_inplace << " milliseconds." << std::endl;

	// 2. time encrypting nr_of_messages with inplace
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		sc.decrypt(decrypted_inplace,
			ciphertext,
			nonce,
			mac);
	}
	auto t11 = system_clock::now();
	auto t_inplace = duration_cast<milliseconds>(t11 - t10).count();

	os << "Decrypting detached " << nr_of_messages << " messages (in-place): "
		<< t_inplace << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(t_inplace < t_no_inplace,
		"sodium::secretbox::decrypt(inplace) detached slower than sodium::box::decrypt() ???");
}

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

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
  BOOST_CHECK(test_of_correctness_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
  BOOST_CHECK(test_of_correctness_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_full_plaintext_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_empty_plaintext_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_ciphertext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_mac )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_key )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, false, false, true, false));
  BOOST_CHECK(test_of_correctness_inplace(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_nonce )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, false, false, false, true));
  BOOST_CHECK(test_of_correctness_inplace(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_mac_empty )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext, false, true));
  BOOST_CHECK(test_of_correctness_inplace(plaintext, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_ciphertext_and_mac )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext, true, true, false, false));
  BOOST_CHECK(test_of_correctness_inplace(plaintext, true, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_ciphertext_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, true, false, false, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, true, false, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_mac_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, true, false, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_key_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, true, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_nonce_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, false, true));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_mac_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, true, false, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, true, false, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_key_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, true, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, false, true, false));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_nonce_empty_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_detached(plaintext, false, false, false, true));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, false, false, false, true));
}

BOOST_AUTO_TEST_CASE( sodium_secretbox_test_falsify_ciphertext_and_mac_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_detached(plaintext, true, true, false, false));
  BOOST_CHECK(test_of_correctness_detached_inplace(plaintext, true, true, false, false));
}

BOOST_AUTO_TEST_CASE(sodium_secretbox_test_time_encrypt)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	time_encrypt<>(5000000);
	time_encrypt_detached<>(5000000);
}

BOOST_AUTO_TEST_CASE(sodium_secretbox_test_time_decrypt)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	time_decrypt<>(5000000);
	time_decrypt_detached<>(5000000);
}

BOOST_AUTO_TEST_SUITE_END ()
