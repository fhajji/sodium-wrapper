// test_Key.cpp -- Test Sodium::Key<>
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

// To see something useful during the tests of the copy vs. move
// c'tors and assignments, uncomment the line #define NDEBUG in
// include/alloc.h.
//
// Then, invoke like this:
//   build_tests/test_Key --run_test=sodium_test_suite/sodium_test_key_copy_ctor
//   build/tests/test_Key --run_test=sodium_test_suite/sodium_test_key_move_ctor
//   build/tests/test_Key --run_test=sodium_test_suite/sodium_test_key_copy_assign
//   build/tests/test_Key --run_test=sodium_test_suite/sodium_test_key_move_assignment
//
// To see output of sodium_test_key_select_copy_or_move, run like this:
//   build/tests/test_Key ---run_test=sodium_test_suite/sodium_test_key_select_copy_or_move --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::Key Test
#include <boost/test/included/unit_test.hpp>

#include <algorithm>
#include <utility>
#include <stdexcept>
#include <string>

#include <sodium.h>

#include "common.h"
#include "key.h"

using Sodium::Key;
using data_t = Sodium::data_t;

static constexpr std::size_t ks1     = Sodium::KEYSIZE_SECRETBOX;
static constexpr std::size_t ks2     = Sodium::KEYSIZE_AUTH;
static constexpr std::size_t ks3     = Sodium::KEYSIZE_AEAD;
static constexpr std::size_t ks_salt = Sodium::KEYSIZE_SALT;
static constexpr std::size_t ks_pub  = Sodium::KEYSIZE_PUBKEY;
static constexpr std::size_t ks_priv = Sodium::KEYSIZE_PRIVKEY;
static constexpr std::size_t ks_seed = Sodium::KEYSIZE_SEEDBYTES;

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

template <std::size_t KEYSIZE>
void selectKey(const Key<KEYSIZE> &key)
{
  BOOST_TEST_MESSAGE("selectKey(const Key<KEYSIZE> &) invoked");

  BOOST_CHECK(key.size() != 0);
}

template <std::size_t KEYSIZE>
void selectKey(Key<KEYSIZE> &&key)
{
  BOOST_TEST_MESSAGE("selectKey(Key<KEYSIZE> &&) invoked");

  Key<KEYSIZE> internalKey {std::move(key)}; // pilfer resources from parameter
  
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_key_size )
{
  Key<ks1> key;

  BOOST_CHECK_EQUAL(key.size(), ks1);
  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_noinit )
{
  Key<ks2> key {false};

  BOOST_CHECK(isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
  
  key.initialize();

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks2);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_init )
{
  Key<ks2> key;

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_copy_ctor )
{
  Key<ks_salt> key;

  // we MUST NOT remove access to key prior to copy c'tor,
  // or we'll crash the program here:
  // key.noaccess();
  
  Key<ks_salt> key_copy(key); // copy c'tor

  // restore access to key for further testing:
  // key.readonly();
  
  BOOST_CHECK(key == key_copy); // test operator==()
  BOOST_CHECK(key.size() == key_copy.size());
  BOOST_CHECK(isSameBytes(key.data(), key.size(),
			  key_copy.data(), key_copy.size()));

  // both keys have different key_t pages in protected memory
  BOOST_CHECK(key.data() != key_copy.data());
}

BOOST_AUTO_TEST_CASE( sodium_test_key_copy_assign )
{
  Key<ks3> key;
  Key<ks3> key_copy {false}; // no init

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

BOOST_AUTO_TEST_CASE( sodium_test_key_setpass )
{
  data_t salt1(ks_salt);
  randombytes_buf(salt1.data(), salt1.size());

  std::string pw1 { "CPE1704TKS" };
  std::string pw2 { "12345" };

  Key<ks3> key1 {false};
  key1.setpass(pw1, salt1, Key<ks3>::strength_t::medium);
  BOOST_CHECK(! isAllZero(key1.data(), key1.size()));
  
  Key<ks3> key2 {false};
  key2.setpass(pw1, salt1, Key<ks3>::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));

  // invoking setpass() with the same parameters must yield the
  // same bytes
  BOOST_CHECK(isSameBytes(key1.data(), key1.size(),
			  key2.data(), key2.size()));
  
  // invoking setpass() with different password must yield
  // different bytes
  key2.setpass(pw2, salt1, Key<ks3>::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password but different salt
  // must yield different bytes
  data_t salt2(ks_salt);
  randombytes_buf(salt2.data(), salt2.size());
  key2.setpass(pw1, salt2, Key<ks3>::strength_t::medium);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // invoking setpass() with same password, same salt, but
  // different strength, must yield different bytes
  key2.setpass(pw1, salt1, Key<ks3>::strength_t::low);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
  
  BOOST_CHECK(! isSameBytes(key1.data(), key1.size(),
			    key2.data(), key2.size()));

  // try memory / cpu intensive key generation (patience...)
  key2.setpass(pw1, salt1, Key<ks3>::strength_t::high);
  BOOST_CHECK(! isAllZero(key2.data(), key2.size()));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_destroy )
{
  Key<ks1> key;

  BOOST_CHECK(! isAllZero(key.data(), key.size()));
  BOOST_CHECK_EQUAL(key.size(), ks1);
  
  key.destroy(); // key.readwrite() is implicit here!

  BOOST_CHECK(isAllZero(key.data(), key.size())); // must be all-zero now!
  BOOST_CHECK_EQUAL(key.size(), ks1);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_empty_key )
{
  Key<> key(false);  // default constructor: empty key with 0 bytes.

  // XXX: an empty key MUST be created with false, so that it
  // remains readwrite(). Calling it without arguments will
  // try a readonly(), which will crash the program with a
  // "no mapping at fault address" (because mprotect() on a
  // 0-page won't work).

  // We need a template specialization for Key<> that handles
  // this case separately...
  
  BOOST_CHECK_EQUAL(key.size(), 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_move_ctor )
{
  Key<ks1> key;                       // create random key
  auto key_data = key.data();

  Key<ks1> key_copy {key};            // copy c'tor

  // it doesn't harm to remove access prior to move c'tor...
  key.noaccess();
  
  Key<ks1> key_move {std::move(key)}; // move c'tor, key is now invalid
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
  Key<> key_empty(false);
  BOOST_CHECK(key == key_empty);

  // XXX: even if ks1 != 0, key == key_empty after they have been
  // both emptied?
  
  // both key and key_move had the same key_t representation in memory
  BOOST_CHECK(key_data == key_move_data);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_move_assignment )
{
  Key<ks1> key;                  // create random key
  auto key_data = key.data();
  
  Key<ks1> key_copy {key};       // copy c'tor
  Key<ks1> key2;                 // create another random key
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
  Key<> key_empty(false);
  BOOST_CHECK(key == key_empty); // XXX

  // both key and key2 had the same key_t representation in memory
  BOOST_CHECK(key_data == key2_data_new);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_std_move_doesnt_empty_key )
{
  Key<ks1> key;

  BOOST_CHECK(key.size() != 0);

  // merely calling std::move(key) doesn't empty the key of its
  // resources.
  
  // If we don't explicitely do something that invokes
  // a Key move constructor as in
  // 
  //      Key<SIZE> newKey {std::move(key)};
  //
  // or a Key move assignment operator, as in
  // 
  //      Key<SIZE> newKey = std::move(key);
  //
  // key itself will remain untouched and unharmed:
  
  BOOST_CHECK((std::move(key)).size() != 0);
  BOOST_CHECK(key.size() != 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_select_copy_or_move )
{
  Key<ks1> key;

  // interestingly, this doesn't generate a new key_t allocation:
  selectKey(key);            // calls selectKey(const Key &);

  // this doesn't either, but that was expected not to:
  selectKey(std::move(key)); // calls selectKey(Key &&);

  // after emptying key of its resources, selectKey(Key &&) has left
  // key as an empty shell:
  
  Key<> key_empty(false);
  BOOST_CHECK(key.size() == 0);
  BOOST_CHECK(key == key_empty);

  // note that had selectKey(Key &&) not explicitely pilfered the
  // resources from its key parameter, key here wouldn't be empty.
}

// NYI: add test cases for readwrite(), readonly() and noaccess()...

BOOST_AUTO_TEST_SUITE_END ();
