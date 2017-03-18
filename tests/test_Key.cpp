// test_Key.cpp -- Test Sodium::Key
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
#define BOOST_TEST_MODULE Sodium::Key Test
#include <boost/test/included/unit_test.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>

#include <sodium.h>

#include "common.h"
#include "key.h"

using Sodium::Key;
using data_t = Sodium::data_t;

static constexpr std::size_t ks1     = Key::KEYSIZE_SECRETBOX;
static constexpr std::size_t ks2     = Key::KEYSIZE_AUTH;
static constexpr std::size_t ks3     = Key::KEYSIZE_AEAD;
static constexpr std::size_t ks_salt = Key::KEYSIZE_SALT;
static constexpr std::size_t ks_pub  = Key::KEYSIZE_PUBKEY;
static constexpr std::size_t ks_priv = Key::KEYSIZE_PRIVKEY;
static constexpr std::size_t ks_seed = Key::KEYSIZE_SEEDBYTES;

bool isAllZero(const unsigned char *bytes, const std::size_t &size)
{
  return std::all_of(bytes, bytes+size,
		     [](unsigned char byte){return byte == '\0';});
}

bool isSameBytes(const unsigned char *bytes1, const std::size_t &size1,
		 const unsigned char *bytes2, const std::size_t &size2)
{
  if (size1 != size2)
    throw std::runtime_error {"isSameBytes(): not same size"};

  return std::equal(bytes1, bytes1+size1,
		    bytes2);
}

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_key_size )
{
  Key key(ks1);

  BOOST_CHECK_EQUAL(key.size(), ks1);
  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_noinit )
{
  Key key(ks2, false);

  BOOST_CHECK(isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
  
  key.initialize();

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_init )
{
  Key key(ks2);

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_copy_ctor )
{
  Key key(ks_salt);
  Key key_copy(key); // copy c'tor

  BOOST_CHECK(key == key_copy); // test operator==()
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(isSameBytes(key.data(), key.size(),
			  key_copy.data(), key_copy.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_copy_assign )
{
  Key key(ks3);
  Key key_copy(ks3, false); // no init

  BOOST_CHECK(key != key_copy); // test operator!=()
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(! isSameBytes(key.data(), key.size(),
			    key_copy.data(), key_copy.size()));
  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK(isAllZero(key_copy.data(), key_copy.size()));

  key_copy = key; // copy-assign

  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(isSameBytes(key.data(), key.size(),
			  key_copy.data(), key_copy.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_setpass )
{
  data_t salt1(ks_salt);
  randombytes_buf(salt1.data(), salt1.size());

  std::string pw1 { "CPE1704TKS" };
  std::string pw2 { "12345" };

  Key key1(ks3, false);
  key1.setpass(pw1, salt1, Key::strength_t::medium);
  BOOST_CHECK(! isAllZero(key1.data(), key1.size()));
  
  Key key2(ks3, false);
  key2.setpass(pw1, salt1, Key::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));

  // invoking setpass() with the same parameters must yield the
  // same bytes
  BOOST_CHECK(isSameBytes(key1.data(), key1.size(),
			  key2.data(), key2.size()));
  
  // invoking setpass() with different password must yield
  // different bytes
  key2.setpass(pw2, salt1, Key::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password but different salt
  // must yield different bytes
  data_t salt2(ks_salt);
  randombytes_buf(salt2.data(), salt2.size());
  key2.setpass(pw1, salt2, Key::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password, same salt, but
  // different strength, must yield different bytes
  key2.setpass(pw1, salt1, Key::strength_t::low);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // try memory / cpu intensive key generation (patience...)
  key2.setpass(pw1, salt1, Key::strength_t::high);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_destroy )
{
  Key key(ks1);

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks1);
  
  key.destroy(); // key.readwrite() is implicit here!

  BOOST_CHECK(isAllZero(key.data(), key.size())); // must be all-zero now!
  BOOST_CHECK_EQUAL(key.size(), ks1);
}

// NYI: add test cases for readwrite(), readonly() and noaccess()...

BOOST_AUTO_TEST_SUITE_END ();
