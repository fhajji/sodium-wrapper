// test_salsa20_filter.cpp -- Test sodium::salsa20_filter
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
#define BOOST_TEST_MODULE sodium::salsa20_filter Test
#include <boost/test/included/unit_test.hpp>

#include "salsa20_filter.h"
#include "common.h"

#include <string>
#include <stdexcept>    // std::runtime_error
#include <algorithm>    // std::equal(), std::copy()
#include <iterator>     // std::back_inserter
#include <cstdio>       // std::remove()

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/tee.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using sodium::salsa20_filter;
using sodium::tohex;
using chars = sodium::chars;

namespace io = boost::iostreams;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

void
delete_file(const char *fname)
{
	int result = std::remove(fname);

	BOOST_CHECK(result == 0);
}

bool
test_of_correctness_combined_output_filter(const std::string &plaintext)
{
  chars plainblob { plaintext.cbegin(), plaintext.cend() };

  salsa20_filter::key_type   key;   // Create a random key
  salsa20_filter::nonce_type nonce; // Create a random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  salsa20_filter decrypt_filter {12, key, nonce};
  
  chars decrypted (2 * plaintext.size()); // because of both writes below

  io::array_sink        sink {decrypted.data(), decrypted.size()};
  io::filtering_ostream os   {};
  os.push(encrypt_filter); // first encrypt
  os.push(decrypt_filter); // then decrypt again
  os.push(sink);           // and store result in sink/derypted.

  os.write(plainblob.data(), plainblob.size());
  os.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  os.flush();

  os.pop();

  // sink (i.e. decrypted) has been hopefully filled with decrypted text

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(), plainblob.cend()));
  BOOST_TEST_MESSAGE(std::string(decrypted.cbegin(), decrypted.cend()));
  
  // because we've sent plainblob TWICE with os.write() to the sink,
  // decrypted == (plainblob || plainblob).

  BOOST_CHECK_EQUAL(decrypted.size(), 2 * plainblob.size());

  if (plaintext.empty())
    return decrypted == plainblob;
  else
    return
      std::equal(decrypted.cbegin(), decrypted.cbegin() + plaintext.size(),
		 plainblob.cbegin())
      &&
      std::equal(decrypted.cbegin() + plaintext.size(), decrypted.cend(),
		 plainblob.cbegin());
}

bool
test_of_correctness_combined_input_filter(const std::string &plaintext)
{
  chars plainblob  { plaintext.cbegin(), plaintext.cend() };
  chars plainblob2 {plainblob};
  std::copy(plainblob.cbegin(), plainblob.cend(),
	    std::back_inserter(plainblob2)); // plainblob2 = (plainblob || plainblob)
  
  salsa20_filter::key_type   key;   // Create a random key
  salsa20_filter::nonce_type nonce; // Create a random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  salsa20_filter decrypt_filter {12, key, nonce};
  
  chars decrypted (2 * plaintext.size()); // because of plainblob2 above

  io::array_source      source {plainblob2.data(), plainblob2.size()};
  io::filtering_istream is     {};
  is.push(decrypt_filter); // then decrypt again
  is.push(encrypt_filter); // first encrypt
  is.push(source);         // data to be encrypted in source/plainblob2.

  is.read(decrypted.data(), decrypted.size());
  
  is.pop();

  BOOST_CHECK(is); // stream must remain valid after successful decryption
  
  // variable decrypted has been hopefully filled with decrypted text

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(), plainblob.cend()));
  BOOST_TEST_MESSAGE(std::string(decrypted.cbegin(), decrypted.cend()));
  
  // because we've sent plainblob TWICE to the
  //    source -> encrypt_filter | decrypt_filter:
  // decrypted == (plainblob || plainblob).

  BOOST_CHECK_EQUAL(decrypted.size(), 2 * plainblob.size());

  if (plaintext.empty())
    return decrypted.empty();
  else
    return decrypted == plainblob2;
}

bool
test_of_correctness_output_filter(const std::string &plaintext,
				  bool falsify_ciphertext=false,
				  bool falsify_key=false,
				  bool falsify_nonce=false)
{
  chars plainblob  { plaintext.cbegin(), plaintext.cend() };
  
  salsa20_filter::key_type   key;    // Create a random key
  salsa20_filter::key_type   key2;   // Create another random key
  salsa20_filter::nonce_type nonce;  // Create a random nonce
  salsa20_filter::nonce_type nonce2; // Create another random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  salsa20_filter decrypt_filter {12,
                                 (falsify_key   ? key2   : key),
                                 (falsify_nonce ? nonce2 : nonce)};

  // 1. encrypt from source/plainblob into ciphertext:
  
  chars ciphertext ( 2*plaintext.size() );

  io::array_sink          sink1 {ciphertext.data(), ciphertext.size()};
  io::filtering_ostream   os1   {};
  os1.push(encrypt_filter); // encrypt
  os1.push(sink1);          // then store result in sink/ciphertext.

  os1.write(plainblob.data(), plainblob.size());
  os1.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  
  os1.pop();

  // sink1 (i.e. ciphertext) contains ciphertext (without MAC)

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(),  plainblob.cend()));
  BOOST_TEST_MESSAGE(tohex(ciphertext));
  
  BOOST_CHECK_EQUAL(ciphertext.size(), 2*plainblob.size());

  // plainblob2 != ciphertext if and only if plaintext was not empty!
  chars plainblob2 { plainblob };
  std::copy(plainblob.cbegin(), plainblob.cend(),
	    std::back_inserter(plainblob2));
  
  if (plaintext.empty())
    BOOST_CHECK(plainblob2 == ciphertext);
  else
    BOOST_CHECK(plainblob2 != ciphertext);

  if (! plaintext.empty() && falsify_ciphertext) {
    // ciphertext is of the form: actual_ciphertext (without MAC)
    ++ciphertext[0]; // falsify ciphertext
  }

  // 2. decrypt from source/ciphertext into decrypted

  chars decrypted (ciphertext.size());

  io::array_sink          sink2 {decrypted.data(), decrypted.size()};
  io::filtering_ostream   os2   {};
  os2.push(decrypt_filter); // (attempt to) decrypt
  os2.push(sink2);          // then store result in sink/ciphertext.

  os2.write(ciphertext.data(), ciphertext.size());

  os2.pop();
  
  // sink2 (i.e. decrypted) has been hopefully filled with decrypted text

  BOOST_TEST_MESSAGE(std::string(decrypted.cbegin(), decrypted.cend()));
  
  BOOST_CHECK_EQUAL(decrypted.size(), 2*plainblob.size());

  // decryption succeeded and plainblob2 == decrypted if and only if
  // we don't falsify the ciphertext
  // nor the key nor the nonce.

  if (falsify_ciphertext || falsify_key || falsify_nonce)
    return plainblob2 != decrypted;
  else
    return plainblob2 == decrypted;
}

bool
test_of_correctness_input_filter(const std::string &plaintext,
				 bool falsify_ciphertext=false,
				 bool falsify_key=false,
				 bool falsify_nonce=false)
{
  chars plainblob  { plaintext.cbegin(), plaintext.cend() };
  chars plainblob2 { plainblob };
  std::copy(plainblob.cbegin(), plainblob.cend(),
	    std::back_inserter(plainblob2));
  
  salsa20_filter::key_type   key;    // Create a random key
  salsa20_filter::key_type   key2;   // Create another random key
  salsa20_filter::nonce_type nonce;  // Create a random nonce
  salsa20_filter::nonce_type nonce2; // Create another random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  salsa20_filter decrypt_filter {12,
                                 (falsify_key   ? key2   : key),
                                 (falsify_nonce ? nonce2 : nonce)};

  // 1. encrypt plainblob2 into ciphertext
  
  chars ciphertext ( 2*plaintext.size() );

  io::array_source        source1 {plainblob2.data(), plainblob2.size()};
  io::filtering_istream   is1   {};
  is1.push(encrypt_filter); // encrypt data
  is1.push(source1);        // ... stored in source1/plainblob2.

  // read computed ciphertext into variable ciphertext
  is1.read(ciphertext.data(), ciphertext.size());
  
  is1.pop();

  // variable ciphertext now contains ciphertext (without MAC)

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(), plainblob.cend()));
  BOOST_TEST_MESSAGE(tohex(ciphertext));

  BOOST_CHECK_EQUAL(ciphertext.size(), 2*plainblob.size());

  // plainblob2 != ciphertext if and only if plaintext was not empty!
  
  if (plaintext.empty())
    BOOST_CHECK(ciphertext.empty());
  else
    BOOST_CHECK(plainblob2 != ciphertext);

  if (! plaintext.empty() && falsify_ciphertext) {
    // ciphertext is of the form: actual_ciphertext (without MAC)
    ++ciphertext[0]; // falsify ciphertext
  }

  // 2. decrypt ciphertext into decrypted

  chars decrypted (ciphertext.size());

  io::array_source        source2 {ciphertext.data(), ciphertext.size()};
  io::filtering_istream   is2   {};
  is2.push(decrypt_filter); // (attempt to) decrypt data...
  is2.push(source2);        // ... stored in source2/ciphertext

  // read decrypted result into decrypted:
  is2.read(decrypted.data(), decrypted.size());

  is2.pop();

  BOOST_CHECK(is2); // after decryption, stream must remain valid
  
  // variable decrypted has been hopefully filled with decrypted text

  BOOST_TEST_MESSAGE(std::string(decrypted.cbegin(), decrypted.cend()));
  
  BOOST_CHECK_EQUAL(decrypted.size(), 2*plainblob.size());

  // decryption succeeded and plainblob2 == decrypted if and only if
  // we don't falsify the ciphertext
  // nor the key nor the nonce.

  if (falsify_ciphertext || falsify_key || falsify_nonce)
    return plainblob2 != decrypted;
  else
    return plainblob2 == decrypted;
}

void
length_test_output_filter(const std::string &plaintext)
{
  chars plainblob  { plaintext.cbegin(), plaintext.cend() };
  
  salsa20_filter::key_type   key;   // Create a random key
  salsa20_filter::nonce_type nonce; // Create a random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  
  chars ciphertext (plainblob.size());

  io::array_sink        sink {ciphertext.data(), ciphertext.size()};
  io::filtering_ostream os   {};
  os.push(encrypt_filter); // first encrypt
  os.push(sink);           // and store result in sink/ciphertext.

  os.write(plainblob.data(), plainblob.size());
  os.flush();

  os.pop();

  // sink (i.e. ciphertext) has been hopefully filled with ciphertext

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(), plainblob.cend()));
  BOOST_TEST_MESSAGE(tohex(ciphertext));

  // unless plaintext was empty, in which case ciphertext is also empty,
  // check that plaintext and ciphertext aren't the same:
  if (plaintext.empty())
    BOOST_CHECK(ciphertext == plainblob);
  else
    BOOST_CHECK(ciphertext != plainblob);
  
  BOOST_CHECK_EQUAL(ciphertext.size(),
		    plaintext.size());
}

void
length_test_input_filter(const std::string &plaintext)
{
  chars plainblob  { plaintext.cbegin(), plaintext.cend() };

  salsa20_filter::key_type   key;   // Create a random key
  salsa20_filter::nonce_type nonce; // Create a random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  
  chars ciphertext (plainblob.size());

  io::array_source      source {plainblob.data(), plainblob.size()};
  io::filtering_istream is   {};
  is.push(encrypt_filter); // encrypt from ...
  is.push(source);         // data stored in source/plainblob.

  // read result into ciphertext
  is.read(ciphertext.data(), ciphertext.size());
  
  is.pop();

  BOOST_CHECK(is); // after encryption, stream must still be ready
  
  // variable ciphertext has been hopefully filled with ciphertext

  BOOST_TEST_MESSAGE(std::string(plainblob.cbegin(), plainblob.cend()));
  BOOST_TEST_MESSAGE(tohex(ciphertext));
  
  // unless plaintext was empty, in which case ciphertext is also empty,
  // check that plaintext and ciphertext aren't the same:
  if (plaintext.empty())
    BOOST_CHECK(ciphertext == plainblob);
  else
    BOOST_CHECK(ciphertext != plainblob);
  
  BOOST_CHECK_EQUAL(ciphertext.size(),
		    plaintext.size());
}

void
pipeline_output_device (const std::string &plaintext,
			const std::string &encfile_name,
			const std::string &decfile_name)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  salsa20_filter::key_type   key;   // Create a random key
  salsa20_filter::nonce_type nonce; // Create a random nonce

  salsa20_filter encrypt_filter {10, key, nonce};
  salsa20_filter decrypt_filter {12, key, nonce};

  io::file_sink encfile {encfile_name,
                         std::ios_base::out | std::ios_base::binary };
  io::file_sink decfile {decfile_name,
                         std::ios_base::out | std::ios_base::binary };

  io::tee_filter<io::file_sink> tee_filter(encfile);
  
  io::filtering_ostream os(encrypt_filter | tee_filter |
		           decrypt_filter | decfile);

  os.write(plainblob.data(), plainblob.size());

  os.flush();
}

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_size_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  length_test_output_filter(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_size_empty_output_filter )
{
  std::string plaintext {};
  length_test_output_filter(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_size_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  length_test_input_filter(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_size_empty_input_filter )
{
  std::string plaintext {};
  length_test_input_filter(plaintext);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_combined_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_combined_output_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_combined_empty_output_filter )
{
  std::string plaintext {};
  auto result = test_of_correctness_combined_output_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_combined_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_combined_input_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_combined_empty_input_filter )
{
  std::string plaintext {};
  auto result = test_of_correctness_combined_input_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_output_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_ciphertext_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_output_filter(plaintext, true, false, false);

  // Test must succeed, we falsified the ciphertext but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_key_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_output_filter(plaintext, false, true, false);

  // Test must succeed, we falsified the key but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_nonce_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_output_filter(plaintext, false, false, true);

  // Test must succeed, we falsified the nonce but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_input_filter(plaintext);

  // Test must succeed
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_ciphertext_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_input_filter(plaintext, true, false, false);

  // Test must succeed, we falsified the ciphertext but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_key_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_input_filter(plaintext, false, true, false);

  // Test must succeed, we falsified the key but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_correctness_falsify_nonce_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = test_of_correctness_input_filter(plaintext, false, false, true);

  // Test must succeed, we falsified the nonce but caught it!
  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_salsa20_filter_pipeline_output_device )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  pipeline_output_device(plaintext,
			 "outfile3.enc",
			 "outfile3.dec");

  // Test succeeds if outfile3.dec contains plaintext
  chars plainblob {plaintext.cbegin(), plaintext.cend()};
  
  io::file_source is("outfile3.dec",
		     std::ios_base::in | std::ios_base::binary);
  chars decrypted(plaintext.size());
  is.read(decrypted.data(), decrypted.size());
  is.close(); // so we can delete file before is goes out of scope

  BOOST_CHECK(decrypted == plainblob);

  delete_file("outfile3.enc");
  delete_file("outfile3.dec");
}

// NYI: add test cases to prove that we used salsa20 correctly...
// i.e. compare with crypto_stream_salsa20_xor() on the whole input.

BOOST_AUTO_TEST_SUITE_END ()
