// test_auth_filters.cpp -- Test sodium::auth_{mac,verify}_filter
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
#define BOOST_TEST_MODULE sodium::auth_filters Test
#include <boost/test/included/unit_test.hpp>

#include "auth_mac_filter.h"
#include "auth_verify_filter.h"
#include "authenticator.h"
#include "common.h"

#include <string>

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using sodium::auth_mac_filter;
using sodium::auth_verify_filter;
using chars = sodium::chars;
using authenticator = sodium::authenticator<chars>; // NOT bytes!

namespace io = boost::iostreams;

static constexpr std::size_t macsize = auth_verify_filter::MACSIZE;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

unsigned char
mac_verify_output_filter(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;     // create a random key
  authenticator sa{ std::move(key) }; // create a chars authenticator
  auth_mac_filter mac_filter{ sa };   // create a MAC creator filter

  // note above: we pass a COPY of sa to mac_filter
  // instead of std::move()ing it, since we still
  // need sa below.

  chars mac(macsize); // where to store MAC
  
  io::array_sink        sink1 {mac.data(), mac.size()};
  io::filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);
  
  // 2: verify the MAC with auth_verify_filter:

  // create a verifyer filter, reusing our authenticator sa
  // note: we std::move(sa), since we don't need it later.
  auth_verify_filter verify_filter {std::move(sa), mac};
  chars result(1);
  
  io::array_sink         sink2 {result.data(), result.size()};
  io::filtering_ostream  os2 {};
  os2.push(verify_filter);
  os2.push(sink2);

  os2.write(plainblob.data(), plainblob.size());
  os2.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  os2.flush();

  os2.pop();

  // the result is in sink2, i.e. in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must verify
  // BOOST_CHECK_EQUAL(result[0], '1');

  return result[0];
}

unsigned char
mac_verify_input_filter(const std::string &plaintext)
{
  chars       plainblob {plaintext.cbegin(), plaintext.cend()};
  chars       plainblob2 {plainblob};
  std::copy(plainblob.cbegin(), plainblob.cend(),
	    std::back_inserter(plainblob2)); // plainblob2 = plainblob + plainblob
  
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;
  authenticator sa{ std::move(key) };
  auth_mac_filter mac_filter{ sa };  // reuse sa below

  chars mac(macsize); // where to store MAC
  
  io::array_source      source1 {plainblob2.data(), plainblob2.size()};
  io::filtering_istream is1 {};
  is1.push(mac_filter);
  is1.push(source1);

  is1.read(mac.data(), mac.size());
  
  is1.pop();

  // mac has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);
  
  // 2: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {std::move(sa), mac};
  chars              result(1);
  
  io::array_source       source2 {plainblob2.data(), plainblob2.size()};
  io::filtering_istream  is2 {};
  is2.push(verify_filter);
  is2.push(source2);

  is2.read(result.data(), result.size());
  
  is2.pop();

  // the result is in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must verify
  // BOOST_CHECK_EQUAL(result[0], '1');

  return result[0];
}

unsigned char
falsify_mac_output_filter(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  authenticator   sa{ auth_mac_filter::key_type() };
  auth_mac_filter mac_filter{ sa };

  chars mac(macsize); // where to store MAC
  
  io::array_sink        sink1 {mac.data(), mac.size()};
  io::filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2. falsify the MAC
  if (mac.size() != 0)
    ++mac[0];

  // 3: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter{ std::move(sa), mac };
  chars              result(1);
  
  io::array_sink         sink2 {result.data(), result.size()};
  io::filtering_ostream  os2 {};
  os2.push(verify_filter);
  os2.push(sink2);

  os2.write(plainblob.data(), plainblob.size());
  os2.flush();

  os2.pop();

  // the result is in sink2, i.e. in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify
  // BOOST_CHECK_EQUAL(result[0], '0');

  return result[0];
}

unsigned char
falsify_mac_input_filter(const std::string &plaintext)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1: compute a MAC with auth_mac_filter:
  authenticator   sa;               // with random key
  auth_mac_filter mac_filter{ sa }; // reuse sa below

  chars mac(macsize); // where to store MAC
  
  io::array_source      source1 {plainblob.data(), plainblob.size()};
  io::filtering_istream is1 {};
  is1.push(mac_filter);
  is1.push(source1);

  is1.read(mac.data(), mac.size());

  is1.pop();

  // mac has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2. falsify the MAC
  if (mac.size() != 0)
    ++mac[0];

  // 3: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {std::move(sa), mac};
  chars              result(1);
  
  io::array_source       source2 {plainblob.data(), plainblob.size()};
  io::filtering_istream  is2 {};
  is2.push(verify_filter);
  is2.push(source2);

  is2.read(result.data(), result.size());
  
  is2.pop();

  // the result is in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify
  // BOOST_CHECK_EQUAL(result[0], '0');

  return result[0];
}

unsigned char
falsify_key_output_filter(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;
  authenticator sa{ key };          // reuse key belwo
  auth_mac_filter mac_filter{ sa }; // reuse sa below

  chars mac(macsize); // where to store MAC
  
  io::array_sink        sink1 {mac.data(), mac.size()};
  io::filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2. falsify the key, i.e. create another key
  auth_mac_filter::key_type  key2;    // Create another random key
  BOOST_CHECK(key2 != key);           // very unlikely that they are equal
  authenticator sa2{ std::move(key2) };

  // 3: verify the MAC with auth_verify_filter and new key:

  auth_verify_filter verify_filter {std::move(sa2), mac};
  chars              result(1);
  
  io::array_sink         sink2 {result.data(), result.size()};
  io::filtering_ostream  os2 {};
  os2.push(verify_filter);
  os2.push(sink2);

  os2.write(plainblob.data(), plainblob.size());
  os2.flush();

  os2.pop();

  // the result is in sink2, i.e. in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify
  // BOOST_CHECK_EQUAL(result[0], '0');

  return result[0];
}

unsigned char
falsify_key_input_filter(const std::string &plaintext)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // 1: compute a MAC with auth_mac_filter:
  authenticator   sa; // with random key
  auth_mac_filter mac_filter{ std::move(sa) };

  chars mac(macsize); // where to store MAC
  
  io::array_source      source1 {plainblob.data(), plainblob.size()};
  io::filtering_istream is1 {};
  is1.push(mac_filter);
  is1.push(source1);

  is1.read(mac.data(), mac.size());
  
  is1.pop();

  // mac has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2: verify the MAC with a NEW authenticator:
  // (highly unlikely that both use identical keys)

  auth_verify_filter verify_filter {authenticator(), mac};
  chars              result(1);
  
  io::array_source       source2 {plainblob.data(), plainblob.size()};
  io::filtering_istream  is2 {};
  is2.push(verify_filter);
  is2.push(source2);

  is2.read(result.data(), result.size());
  
  is2.pop();

  // the result is in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify
  // BOOST_CHECK_EQUAL(result[0], '0');

  return result[0];
}

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_size_output_filter )
{
  // use an authenticator with a random key.
  // this is the shorthand version, 
  // it still std::move()s the key / authenticator around).
  // see next test for verbose explicit version.
  auth_mac_filter mac_filter{ authenticator() };

  chars mac(macsize); // where to store MAC
  
  io::array_sink        sink {mac.data(), mac.size()};
  io::filtering_ostream os {};
  os.push(mac_filter);
  os.push(sink);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  chars       plainblob {plaintext.cbegin(), plaintext.cend()};

  os.write(plainblob.data(), plainblob.size());
  os.flush();

  os.pop();

  // sink (i.e. mac) has been filled with MAC:

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_size_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  chars       plainblob {plaintext.cbegin(), plaintext.cend()};

  // use an authenticator with a random key
  // verbose version, but still efficient:
  // it std::move()s the key and authenticator around.
  // see test above for shorthand version.
  auth_mac_filter::key_type  key;
  authenticator sa{ std::move(key) };
  auth_mac_filter mac_filter{ std::move(sa) };

  chars mac(macsize); // where to store MAC
  
  io::array_source      source {plainblob.data(), plainblob.size()};
  io::filtering_istream is {};
  is.push(mac_filter);
  is.push(source);

  is.read(mac.data(), mac.size());
  
  is.pop();

  // mac has been filled with MAC:

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = mac_verify_output_filter(plaintext);

  // Test must succeed
  BOOST_CHECK_EQUAL(result, '1');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_empty_output_filter )
{
  std::string plaintext {};
  auto result =mac_verify_output_filter(plaintext);

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = mac_verify_input_filter(plaintext);

  // Test must succeed
  BOOST_CHECK_EQUAL(result, '1');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_empty_input_filter )
{
  std::string plaintext {};
  auto result = mac_verify_input_filter(plaintext);

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = falsify_mac_output_filter(plaintext);

  // Test must return '0', i.e. the falsified mac doesn't verify
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_empty_output_filter )
{
  std::string plaintext {};
  auto result = falsify_mac_output_filter(plaintext);

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = falsify_mac_input_filter(plaintext);

  // Test must return '0', i.e. the falsified mac doesn't verify
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_empty_input_filter )
{
  std::string plaintext {};
  auto result = falsify_mac_input_filter(plaintext);

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_full_output_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = falsify_key_output_filter(plaintext);

  // Test must return '0' because verifying with wrong key fails
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_empty_output_filter )
{
  std::string plaintext {};
  auto result = falsify_key_output_filter(plaintext);

  // Test must return 0 (not '0', nor '1') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_full_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto result = falsify_key_input_filter(plaintext);

  // Test must return '0' because verifying with wrong key fails
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_empty_input_filter )
{
  std::string plaintext {};
  auto result = falsify_key_input_filter(plaintext);

  // Test must return 0 (not '0', nor '1') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_plaintext_output_filter )
{
  // 1: compute a MAC with auth_mac_filter:
  authenticator   sa;               // with a random key
  auth_mac_filter mac_filter{ sa }; // reuse sa below

  chars mac(macsize); // where to store MAC
  
  io::array_sink        sink1 {mac.data(), mac.size()};
  io::filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  chars       plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2: falsify plaintext
  if (!plaintext.empty())
    ++plainblob[0]; // falsify plaintext if not empty

  // 3: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {std::move(sa), mac};
  chars              result(1);
  
  io::array_sink         sink2 {result.data(), result.size()};
  io::filtering_ostream  os2 {};
  os2.push(verify_filter);
  os2.push(sink2);

  os2.write(plainblob.data(), plainblob.size());
  os2.flush();

  os2.pop();

  // the result is in sink2, i.e. in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify because we falsified plaintext
  BOOST_CHECK_EQUAL(result[0], '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_plaintext_input_filter )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  chars       plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;
  authenticator sa{ std::move(key) };
  auth_mac_filter mac_filter{ sa };

  chars mac(macsize); // where to store MAC
  
  io::array_source      source1 {plainblob.data(), plainblob.size()};
  io::filtering_istream is1 {};
  is1.push(mac_filter);
  is1.push(source1);

  is1.read(mac.data(), mac.size());
  
  is1.pop();

  // mac has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2: falsify plaintext
  if (!plaintext.empty())
    ++plainblob[0]; // falsify plaintext if not empty
  
  // 3: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {std::move(sa), mac};
  chars              result(1);
  
  io::array_source       source2 {plainblob.data(), plainblob.size()};
  io::filtering_istream  is2 {};
  is2.push(verify_filter);
  is2.push(source2);

  is2.read(result.data(), result.size());
  
  is2.pop();

  // the result is in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must NOT verify, because we falsified plaintext
  BOOST_CHECK_EQUAL(result[0], '0');
}

BOOST_AUTO_TEST_SUITE_END ()
