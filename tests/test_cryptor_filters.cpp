// test_cryptor_filters.cpp -- Test Sodium::cryptor_{encrypt,decrypt}_filter
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
#define BOOST_TEST_MODULE Sodium::cryptor_filters Test
#include <boost/test/included/unit_test.hpp>

#include "cryptor_encrypt_filter.h"
#include "cryptor_decrypt_filter.h"
#include "common.h"

#include <string>
#include <stdexcept>
#include <algorithm>

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using Sodium::cryptor_encrypt_filter;
using Sodium::cryptor_decrypt_filter;
using data_t = Sodium::data_t;

namespace io = boost::iostreams;
typedef io::basic_array_sink<unsigned char>             bytes_array_sink;
typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

bool
test_of_correctness_combined(const std::string &plaintext)
{
  cryptor_encrypt_filter::key_type   key;   // Create a random key
  cryptor_encrypt_filter::nonce_type nonce; // Create a random nonce

  cryptor_encrypt_filter encrypt_filter {key, nonce};
  cryptor_decrypt_filter decrypt_filter {key, nonce};
  
  data_t plainblob { plaintext.cbegin(), plaintext.cend() };
  data_t decrypted (2 * plaintext.size()); // because of both writes below

  bytes_array_sink        sink {decrypted.data(), decrypted.size()};
  bytes_filtering_ostream os   {};
  os.push(encrypt_filter); // first encrypt
  os.push(decrypt_filter); // then decrypt again
  os.push(sink);           // and store result in sink/derypted.

  os.write(plainblob.data(), plainblob.size());
  os.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  os.flush();

  os.pop();

  // sink (i.e. decrypted) has been hopefully filled with decrypted text

  // because we've sent plainblob TWICE with os.write() to the sink,
  // decrypted == (plainblob || plainblob).
  
  return
    std::equal(decrypted.cbegin(), decrypted.cbegin() + plaintext.size(),
	       plainblob.cbegin())
    &&
    std::equal(decrypted.cbegin() + plaintext.size(), decrypted.cend(),
	       plainblob.cbegin());
}

bool
test_of_correctness(const std::string &plaintext,
		    bool falsify_ciphertext=false,
		    bool falsify_mac=false,
		    bool falsify_key=false,
		    bool falsify_nonce=false)
{
  cryptor_encrypt_filter::key_type   key;    // Create a random key
  cryptor_decrypt_filter::key_type   key2;   // Create another random key
  cryptor_encrypt_filter::nonce_type nonce;  // Create a random nonce
  cryptor_decrypt_filter::nonce_type nonce2; // Create another random nonce

  cryptor_encrypt_filter encrypt_filter {key, nonce};
  cryptor_decrypt_filter decrypt_filter {(falsify_key   ? key2   : key),
                                         (falsify_nonce ? nonce2 : nonce)};
  
  data_t plainblob  { plaintext.cbegin(), plaintext.cend() };
  data_t ciphertext ( cryptor_encrypt_filter::MACSIZE + plaintext.size() );

  bytes_array_sink          sink1 {ciphertext.data(), ciphertext.size()};
  bytes_filtering_ostream   os1   {};
  os1.push(encrypt_filter); // encrypt
  os1.push(sink1);          // then store result in sink/ciphertext.

  os1.write(plainblob.data(), plainblob.size());
  
  os1.pop();

  // sink1 (i.e. ciphertext) contains (MAC || ciphertext)

  BOOST_CHECK_EQUAL(ciphertext.size(),
		    cryptor_encrypt_filter::MACSIZE + plainblob.size());

  if (! plaintext.empty() && falsify_ciphertext) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[cryptor_encrypt_filter::MACSIZE]; // falsify ciphertext
  }

  if (falsify_mac) {
    // ciphertext is of the form: (MAC || actual_ciphertext)
    ++ciphertext[0]; // falsify MAC
  }

  try {
    data_t decrypted (ciphertext.size() - cryptor_decrypt_filter::MACSIZE);

    bytes_array_sink          sink2 {decrypted.data(), decrypted.size()};
    bytes_filtering_ostream   os2   {};
    os2.push(decrypt_filter); // (attempt to) decrypt
    os2.push(sink2);          // then store result in sink/ciphertext.

    os2.write(ciphertext.data(), ciphertext.size());

    os2.pop();
  
    // sink2 (i.e. decrypted) has been hopefully filled with decrypted text

    BOOST_CHECK_EQUAL(decrypted.size(), plainblob.size());

    // decryption succeeded and plainblob == decrypted if and only if
    // we don't falsify the ciphertext nor the MAC,
    // nor the key nor the nonce.

    return !falsify_ciphertext &&
      !falsify_mac &&
      !falsify_key &&
      !falsify_nonce &&
      (plainblob == decrypted);
  }
  catch (std::exception &e) {
    // decryption failed. This is expected if and only if we falsified
    // the ciphertext OR we falsified the MAC
    // OR we falsified the key
    // OR we falsified the nonce (or any combination of those)

    return falsify_ciphertext || falsify_mac || falsify_key || falsify_nonce;
  }
  
  // NOTREACHED (hopefully)
  return false;
}

void
length_test(const std::string &plaintext)
{
  cryptor_encrypt_filter::key_type   key;   // Create a random key
  cryptor_encrypt_filter::nonce_type nonce; // Create a random nonce

  cryptor_encrypt_filter encrypt_filter {key, nonce};
  
  data_t plainblob  { plaintext.cbegin(), plaintext.cend() };
  data_t ciphertext (cryptor_encrypt_filter::MACSIZE + plainblob.size());

  bytes_array_sink        sink {ciphertext.data(), ciphertext.size()};
  bytes_filtering_ostream os   {};
  os.push(encrypt_filter); // first encrypt
  os.push(sink);           // and store result in sink/ciphertext.

  os.write(plainblob.data(), plainblob.size());
  os.flush();

  os.pop();

  // sink (i.e. ciphertext) has been hopefully filled with (MAC || ciphertext)

  BOOST_CHECK_EQUAL(ciphertext.size(),
		    cryptor_encrypt_filter::MACSIZE + plaintext.size());
}


BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_size_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  length_test(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_size_empty )
{
  std::string plaintext {};
  length_test(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_combined_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness_combined(plaintext)};

  // Test must succeed
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_combined_empty )
{
  std::string plaintext {};
  auto result           {test_of_correctness_combined(plaintext)};

  // Test must succeed
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness(plaintext)};

  // Test must succeed
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_falsify_ciphertext_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness(plaintext, true, false, false, false)};

  // Test must succeed, we falsified the ciphertext but caught it!
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_falsify_mac_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness(plaintext, false, true, false, false)};

  // Test must succeed, we falsified the MAC but caught it!
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_falsify_key_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness(plaintext, false, false, true, false)};

  // Test must succeed, we falsified the key but caught it!
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_CASE( sodium_test_cryptor_filters_correctness_falsify_nonce_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result {test_of_correctness(plaintext, false, false, false, true)};

  // Test must succeed, we falsified the nonce but caught it!
  BOOST_CHECK_EQUAL(result, true);
}

BOOST_AUTO_TEST_SUITE_END ();
