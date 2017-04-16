// test_auth_filters.cpp -- Test Sodium::auth_{mac,verify}_filter
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
#define BOOST_TEST_MODULE Sodium::auth_filters Test
#include <boost/test/included/unit_test.hpp>

#include "auth_mac_filter.h"
#include "auth_verify_filter.h"
#include "common.h"

#include <string>

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using Sodium::auth_mac_filter;
using Sodium::auth_verify_filter;
using data_t = Sodium::data_t;

namespace io = boost::iostreams;
typedef io::basic_array_sink<unsigned char>             bytes_array_sink;
typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;

static constexpr std::size_t macsize = auth_verify_filter::MACSIZE;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

unsigned char
mac_verify(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;    // Create a random key
  auth_mac_filter mac_filter {key};  // create a MAC creator filter

  data_t mac(macsize); // where to store MAC
  
  bytes_array_sink        sink1 {mac.data(), mac.size()};
  bytes_filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.write(plainblob.data(), plainblob.size()); // simulate multiple writes
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);
  
  // 2: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {key, mac};  // create a MAC verifier filter
  data_t             result(1);                 // result of verify
  
  bytes_array_sink         sink2 {result.data(), result.size()};
  bytes_filtering_ostream  os2 {};
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
falsify_mac(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;    // Create a random key
  auth_mac_filter mac_filter {key};  // create a MAC creator filter

  data_t mac(macsize); // where to store MAC
  
  bytes_array_sink        sink1 {mac.data(), mac.size()};
  bytes_filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  data_t                  plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2. falsify the MAC
  if (mac.size() != 0)
    ++mac[0];

  // 3: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {key, mac};  // create a MAC verifier filter
  data_t             result(1);                 // result of verify
  
  bytes_array_sink         sink2 {result.data(), result.size()};
  bytes_filtering_ostream  os2 {};
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
falsify_key(const std::string &plaintext)
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;    // Create a random key
  auth_mac_filter mac_filter {key};  // create a MAC creator filter

  data_t mac(macsize); // where to store MAC
  
  bytes_array_sink        sink1 {mac.data(), mac.size()};
  bytes_filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2. falsify the key, i.e. create another key
  auth_mac_filter::key_type  key2;    // Create another random key
  BOOST_CHECK(key2 != key);           // very unlikely that they are equal

  // 3: verify the MAC with auth_verify_filter and new key:

  auth_verify_filter verify_filter {key2, mac};  // create a MAC verifier filter
  data_t             result(1);                 // result of verify
  
  bytes_array_sink         sink2 {result.data(), result.size()};
  bytes_filtering_ostream  os2 {};
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_size )
{
  auth_mac_filter::key_type  key;    // Create a random key
  auth_mac_filter mac_filter {key};  // create a MAC creator filter

  data_t mac(macsize); // where to store MAC
  
  bytes_array_sink        sink {mac.data(), mac.size()};
  bytes_filtering_ostream os {};
  os.push(mac_filter);
  os.push(sink);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  os.write(plainblob.data(), plainblob.size());
  os.flush();

  os.pop();

  // sink (i.e. mac) has been filled with MAC:

  BOOST_CHECK_EQUAL(mac.size(), macsize);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto        result    {mac_verify(plaintext)};

  // Test must succeed
  BOOST_CHECK_EQUAL(result, '1');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_mac_verify_empty )
{
  std::string plaintext {};
  auto        result    {mac_verify(plaintext)};

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto        result    {falsify_mac(plaintext)};

  // Test must return '0', i.e. the falsified mac doesn't verify
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_mac_empty )
{
  std::string plaintext {};
  auto        result    {falsify_mac(plaintext)};

  // Test must return 0 (not '1', nor '0') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_full )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  auto        result    {falsify_key(plaintext)};

  // Test must return '0' because verifying with wrong key fails
  BOOST_CHECK_EQUAL(result, '0');
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_key_empty )
{
  std::string plaintext {};
  auto        result    {falsify_key(plaintext)};

  // Test must return 0 (not '0', nor '1') because
  // auth_verify_filter::do_filter() is never called for empty input!
  BOOST_CHECK_EQUAL(result, 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_auth_filters_falsify_plaintext )
{
  // 1: compute a MAC with auth_mac_filter:
  auth_mac_filter::key_type  key;    // Create a random key
  auth_mac_filter mac_filter {key};  // create a MAC creator filter

  data_t mac(macsize); // where to store MAC
  
  bytes_array_sink        sink1 {mac.data(), mac.size()};
  bytes_filtering_ostream os1 {};
  os1.push(mac_filter);
  os1.push(sink1);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t      plainblob {plaintext.cbegin(), plaintext.cend()};

  os1.write(plainblob.data(), plainblob.size());
  os1.flush();

  os1.pop();

  // sink1 (i.e. mac) has been filled with MAC.
  BOOST_CHECK_EQUAL(mac.size(), macsize);

  // 2: verify the MAC with auth_verify_filter:

  auth_verify_filter verify_filter {key, mac};  // create a MAC verifier filter
  data_t             result(1);                 // result of verify
  
  bytes_array_sink         sink2 {result.data(), result.size()};
  bytes_filtering_ostream  os2 {};
  os2.push(verify_filter);
  os2.push(sink2);

  os2.write(plainblob.data(), plainblob.size());
  os2.flush();

  os2.pop();

  // the result is in sink2, i.e. in result[0]:

  BOOST_CHECK_EQUAL(result.size(), 1);
  
  // the MAC must verify
  BOOST_CHECK_EQUAL(result[0], '1');
}

BOOST_AUTO_TEST_SUITE_END ();
