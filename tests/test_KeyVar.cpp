// test_KeyVar.cpp -- Test sodium::KeyVar
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

// To see something useful during the tests of the copy vs. move
// c'tors and assignments, uncomment the line #define NDEBUG in
// include/alloc.h (automatically done in Debug builds).
//
// Then, invoke like this:
//   build_tests/test_KeyVar --run_test=sodium_test_suite/sodium_test_key_copy_ctor
//   build/tests/test_KeyVar --run_test=sodium_test_suite/sodium_test_key_move_ctor
//   build/tests/test_KeyVar --run_test=sodium_test_suite/sodium_test_key_copy_assign
//   build/tests/test_KeyVar --run_test=sodium_test_suite/sodium_test_key_move_assignment
//
// To see output of sodium_test_key_select_copy_or_move, run like this:
//   build/tests/test_KeyVar ---run_test=sodium_test_suite/sodium_test_key_select_copy_or_move --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::KeyVar Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "key.h"
#include "keyvar.h"

#include <utility>
#include <stdexcept>
#include <string>

#include <sodium.h>

using sodium::KeyVar;
using bytes = sodium::bytes;

static constexpr std::size_t ks1     = sodium::KEYSIZE_SECRETBOX;
static constexpr std::size_t ks2     = sodium::KEYSIZE_AUTH;
static constexpr std::size_t ks3     = sodium::KEYSIZE_AEAD;
static constexpr std::size_t ks_salt = sodium::KEYSIZE_SALT;

bool isAllZero(const unsigned char *bytes, const std::size_t &size)
{
  // Don't do this (side channel attack):
  // return std::all_of(bytes, bytes+size,
  // 		     [](unsigned char byte){return byte == '\0';});

  // Compare in constant time instead:
  return sodium_is_zero(bytes, size);
}

bool isSameBytes(const unsigned char *bytes1, const std::size_t &size1,
		 const unsigned char *bytes2, const std::size_t &size2)
{
  if (size1 != size2)
    throw std::runtime_error {"isSameBytes(): not same size"};

  // Don't do this (side channel attack):
  //   return std::equal(bytes1, bytes1+size1,
  // 		    bytes2);

  // Compare in constant time instead:
  return (sodium_memcmp(bytes1, bytes2, size1) == 0);
}

void selectKeyVar(const KeyVar &key)
{
  BOOST_TEST_MESSAGE("selectKeyVar(const KeyVar &) invoked");

  BOOST_CHECK(key.size() != 0);
}

void selectKeyVar(KeyVar &&key)
{
  BOOST_TEST_MESSAGE("selectKeyVar(KeyVar &&) invoked");

  KeyVar internalKey {std::move(key)}; // pilfer resources from parameter
  
  BOOST_CHECK(internalKey.size() != 0);
  BOOST_CHECK(key.size() == 0); // key is now an empty shell
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_size )
{
  KeyVar key(ks1);

  BOOST_CHECK_EQUAL(key.size(), ks1);
  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_noinit )
{
  KeyVar key(ks2, false);

  BOOST_CHECK(isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
  
  key.initialize();

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_init )
{
  KeyVar key(ks2);

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_copy_ctor )
{
  KeyVar key(ks_salt);

  // we MUST NOT remove access to key prior to copy c'tor,
  // or we'll crash the program here:
  // key.noaccess();
  
  KeyVar key_copy(key); // copy c'tor

  // restore access to key for further testing:
  // key.readonly();
  
  BOOST_CHECK(key == key_copy); // test operator==()
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(isSameBytes(key.data(), key.size(),
			  key_copy.data(), key_copy.size()));

  // both keys have different key_t pages in protected memory
  BOOST_CHECK(key.data() != key_copy.data());
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_copy_assign )
{
  KeyVar key(ks3);
  KeyVar key_copy(ks3, false); // no init

  auto key_copy_data = key_copy.data(); // address
  
  BOOST_CHECK(key != key_copy); // test operator!=()
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(! isSameBytes(key.data(), key.size(),
			    key_copy.data(), key_copy.size()));
  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK(isAllZero(key_copy.data(), key_copy.size()));

  // we MUST NOT remove access to key prior to copy-assignment,
  // or we'll crash the program here:
  // key.noaccess();

  // we MUST NOT remove write access to key_copy,
  // because copy-assignment will copy into the same
  // key_t page as already belongs to key_copy
  // (no additional allocation of resources involved)
  // key_copy.readonly();
  
  key_copy = key; // copy-assign

  auto key_copy_data_after_assignment = key_copy.data();

  // copy-assignment didn't allocate a new key_t page;
  // the key didn't move in memory; it just changed values.
  BOOST_CHECK(key_copy_data == key_copy_data_after_assignment);

  // restore access for further testing...
  // key.readonly();
  // key_copy.readonly();
  
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(isSameBytes(key.data(), key.size(),
			  key_copy.data(), key_copy.size()));

  // both keys have different key_t pages in protected memory
  BOOST_CHECK(key.data() != key_copy.data());
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_setpass )
{
  bytes salt1(ks_salt);
  randombytes_buf(salt1.data(), salt1.size());

  std::string pw1 { "CPE1704TKS" };
  std::string pw2 { "12345" };

  KeyVar key1(ks3, false);
  key1.setpass(pw1, salt1, KeyVar::strength_t::medium);
  BOOST_CHECK(! isAllZero(key1.data(), key1.size()));
  
  KeyVar key2(ks3, false);
  key2.setpass(pw1, salt1, KeyVar::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));

  // invoking setpass() with the same parameters must yield the
  // same bytes
  BOOST_CHECK(isSameBytes(key1.data(), key1.size(),
			  key2.data(), key2.size()));
  
  // invoking setpass() with different password must yield
  // different bytes
  key2.setpass(pw2, salt1, KeyVar::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password but different salt
  // must yield different bytes
  bytes salt2(ks_salt);
  randombytes_buf(salt2.data(), salt2.size());
  key2.setpass(pw1, salt2, KeyVar::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password, same salt, but
  // different strength, must yield different bytes
  key2.setpass(pw1, salt1, KeyVar::strength_t::low);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // try memory / cpu intensive key generation (patience...)
  key2.setpass(pw1, salt1, KeyVar::strength_t::high);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_destroy )
{
  KeyVar key(ks1);

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks1);
  
  key.destroy(); // key.readwrite() is implicit here!

  BOOST_CHECK(isAllZero(key.data(), key.size())); // must be all-zero now!
  BOOST_CHECK_EQUAL(key.size(), ks1);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_empty_key )
{
  KeyVar key; // default constructor: empty key with 0 bytes.

  BOOST_CHECK_EQUAL(key.size(), 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_move_ctor )
{
  KeyVar key      (ks1);            // create random key
  auto key_data = key.data();

  KeyVar key_copy {key};            // copy c'tor

  // it doesn't harm to remove access prior to move c'tor...
  key.noaccess();
  
  KeyVar key_move {std::move(key)}; // move c'tor, key is now invalid
  auto key_move_data = key_move.data();
  
  // ... provided that we restored it to the target for more
  // testing further down.
  key_move.readonly();
  
  // we made a key_copy of key, so we can check that key_move
  // and key_copy are essentially the same key material
  
  BOOST_CHECK_EQUAL(key_copy.size(), key_move.size());
  BOOST_CHECK(isSameBytes(key_copy.data(), key_copy.size(),
			  key_move.data(), key_move.size()));

  // key itself must still be valid, but empty,
  // i.e. same as default-constructed with 0 bytes.
  BOOST_CHECK_EQUAL(key.size(), 0);

  // another way to test for empty keys:
  KeyVar key_empty;
  BOOST_CHECK(key == key_empty);

  // both key and key_move had the same key_t representation in memory
  BOOST_CHECK(key_data == key_move_data);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_move_assignment )
{
  KeyVar key      (ks1);       // create random key
  auto key_data = key.data();
  
  KeyVar key_copy {key};       // copy c'tor
  KeyVar key2     (ks2);       // create another random key, even diff size
  auto key2_data = key2.data();
  
  // it doesn't harm to remove access prior to move assignemnt...
  key.noaccess();
  
  key2 = std::move(key); // move-assignement. key is now empty.
  auto key2_data_new = key2.data();

  // old key2 has been overwritten, and doesn't exist anymore.
  // new key2's underlying key_t keydata is at a completely new address.
  BOOST_CHECK(key2_data_new != key2_data);
  
  // ... provided that we restored it for testing further down.
  key2.readonly();
  
  BOOST_CHECK_EQUAL(key2.size(), key_copy.size()); // size has changed!
  BOOST_CHECK(isSameBytes(key_copy.data(), key_copy.size(),
			  key2.data(), key2.size()));

  // key must still be valid, but empty,
  // i.e. same as default-constructed with 0 bytes.
  BOOST_CHECK_EQUAL(key.size(), 0);

  // another way to test for empty keys:
  KeyVar key_empty;
  BOOST_CHECK(key == key_empty);

  // both key and key2 had the same key_t representation in memory
  BOOST_CHECK(key_data == key2_data_new);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_std_move_doesnt_empty_key )
{
  KeyVar key (ks1);

  BOOST_CHECK(key.size() != 0);

  // merely calling std::move(key) doesn't empty the key of its
  // resources.
  
  // If we don't explicitely do something that invokes
  // a Key move constructor as in
  // 
  //      Key newKey {std::move(key)};
  //
  // or a Key move assignment operator, as in
  // 
  //      Key newKey = std::move(key);
  //
  // key itself will remain untouched and unharmed:
  
  BOOST_CHECK((std::move(key)).size() != 0);
  BOOST_CHECK(key.size() != 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_keyvar_select_copy_or_move )
{
  KeyVar key (ks1);

  // interestingly, this doesn't generate a new key_t allocation:
  selectKeyVar(key);            // calls selectKeyVar(const KeyVar &);

  // this doesn't either, but that was expected not to:
  selectKeyVar(std::move(key)); // calls selectKeyVar(KeyVar &&);

  // after emptying key of its resources, selectKeyVar(KeyVar &&) has left
  // key as an empty shell:
  
  KeyVar key_empty;
  BOOST_CHECK(key.size() == 0);
  BOOST_CHECK(key == key_empty);

  // note that had selectKeyVar(KeyVar &&) not explicitely pilfered the
  // resources from its key parameter, key here wouldn't be empty.
}

// NYI: add test cases for readwrite(), readonly() and noaccess()...

BOOST_AUTO_TEST_SUITE_END ()
