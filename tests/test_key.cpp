// test_key.cpp -- Test sodium::key<>
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
// c'tors and assignments, build in Debug mode.
// Then, invoke like this:
//   build_tests/test_key --run_test=sodium_test_suite/sodium_test_key_copy_ctor
//   build/tests/test_key --run_test=sodium_test_suite/sodium_test_key_move_ctor
//   build/tests/test_key --run_test=sodium_test_suite/sodium_test_key_copy_assign
//   build/tests/test_key --run_test=sodium_test_suite/sodium_test_key_move_assignment
//
// To see output of sodium_test_key_select_copy_or_move, run like this:
//   build/tests/test_key ---run_test=sodium_test_suite/sodium_test_key_select_copy_or_move --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::key Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "helpers.h"
#include "key.h"
#include "aead.h" // for sodium::aead<>::KEYSIZE

#include <utility>
#include <stdexcept>
#include <string>

#include <sodium.h>

static constexpr std::size_t ks1     = sodium::KEYSIZE_SECRETBOX;
static constexpr std::size_t ks2     = sodium::KEYSIZE_AUTH;
static constexpr std::size_t ks3     = sodium::aead<>::KEYSIZE;
static constexpr std::size_t ks_salt = sodium::KEYSIZE_SALT;

using bytes = sodium::bytes;

template <std::size_t KEYSIZE>
void selectKey(const sodium::key<KEYSIZE> &key)
{
  BOOST_TEST_MESSAGE("selectKey(const key<KEYSIZE> &) invoked");

  BOOST_TEST(key.size() != 0);
}

template <std::size_t KEYSIZE>
void selectKey(sodium::key<KEYSIZE> &&key)
{
  BOOST_TEST_MESSAGE("selectKey(key<KEYSIZE> &&) invoked");

  sodium::key<KEYSIZE> internalKey {std::move(key)}; // pilfer resources from parameter
  
  BOOST_TEST(internalKey.size() != 0);
  BOOST_TEST(key.size() == 0); // key is now an empty shell
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

BOOST_AUTO_TEST_CASE( sodium_test_key_size )
{
  sodium::key<ks1> key;

  BOOST_TEST(key.size() == ks1);
  BOOST_TEST(!sodium::is_zero(key));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_noinit )
{
  sodium::key<ks2> key {false};

  BOOST_TEST(sodium::is_zero(key));
  BOOST_TEST(key.size() == ks2);
  
  key.initialize();

  BOOST_TEST(!sodium::is_zero(key));
  BOOST_TEST(key.size() == ks2);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_init )
{
  sodium::key<ks2> key;

  BOOST_TEST(!sodium::is_zero(key));
}

BOOST_AUTO_TEST_CASE(sodium_test_key_copy_ctor)
{
	sodium::key<ks_salt> key;

	// we MUST NOT remove access to key prior to copy c'tor,
	// or we'll crash the program here:
	// key.noaccess();

	sodium::key<ks_salt> key_copy{ key }; // copy c'tor

  // restore access to key for further testing:
  // key.readonly();
  
  BOOST_TEST((key == key_copy)); // test operator==()
  BOOST_TEST(key.size() == key_copy.size());
  BOOST_TEST(sodium::compare(key, key_copy));

  // both keys have different key_t pages in protected memory
  BOOST_TEST(key.data() != key_copy.data());
}

BOOST_AUTO_TEST_CASE( sodium_test_key_copy_assign )
{
  sodium::key<ks3> key;
  sodium::key<ks3> key_copy {false}; // no init

  auto key_copy_data = key_copy.data(); // address
  
  BOOST_TEST((key != key_copy)); // test operator!=()
  BOOST_TEST(key.size() == key_copy.size());
  BOOST_TEST(!sodium::compare(key, key_copy));
  BOOST_TEST(!sodium::is_zero(key));
  BOOST_TEST(sodium::is_zero(key_copy));

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
  BOOST_TEST(key_copy_data == key_copy_data_after_assignment);

  // restore access for further testing...
  // key.readonly();
  // key_copy.readonly();
  
  BOOST_TEST((key == key_copy)); // same key _contents_...
  BOOST_TEST(key.size() == key_copy.size());
  BOOST_TEST(sodium::compare(key, key_copy));

  // both keys have different key_type pages in protected memory
  BOOST_TEST(key.data() != key_copy.data()); // ... but different pointers
}

BOOST_AUTO_TEST_CASE( sodium_test_key_setpass )
{
  bytes salt1(ks_salt);
  sodium::randombytes_buf_inplace(salt1);

  std::string pw1 { "CPE1704TKS" };
  std::string pw2 { "12345" };

  sodium::key<ks3> key1 {false};
  key1.setpass(pw1, salt1, sodium::key<ks3>::strength_type::medium);
  BOOST_TEST(!sodium::is_zero(key1));
  
  sodium::key<ks3> key2 {false};
  key2.setpass(pw1, salt1, sodium::key<ks3>::strength_type::medium);
  BOOST_TEST(!sodium::is_zero(key2));

  // invoking setpass() with the same parameters must yield the
  // same bytes
  BOOST_TEST(sodium::compare(key1, key2));
  BOOST_TEST((key1 == key2));
  
  // invoking setpass() with different password must yield
  // different bytes
  key2.setpass(pw2, salt1, sodium::key<ks3>::strength_type::medium);
  BOOST_TEST(!sodium::is_zero(key2));
  
  BOOST_TEST(!sodium::compare(key1, key2));
  BOOST_TEST((key1 != key2));

  // invoking setpass() with same password but different salt
  // must yield different bytes
  bytes salt2(ks_salt);
  sodium::randombytes_buf_inplace(salt2);
  key2.setpass(pw1, salt2, sodium::key<ks3>::strength_type::medium);
  BOOST_TEST(!sodium::is_zero(key2));
  
  BOOST_TEST(!sodium::compare(key1, key2));
  BOOST_TEST((key1 != key2));

  // invoking setpass() with same password, same salt, but
  // different strength, must yield different bytes
  key2.setpass(pw1, salt1, sodium::key<ks3>::strength_type::low);
  BOOST_TEST(!sodium::is_zero(key2));
  
  BOOST_TEST(!sodium::compare(key1, key2));
  BOOST_TEST((key1 != key2));

  // try memory / cpu intensive key generation (patience...)
  key2.setpass(pw1, salt1, sodium::key<ks3>::strength_type::high);
  BOOST_TEST(!sodium::is_zero(key2));
}

BOOST_AUTO_TEST_CASE( sodium_test_key_destroy )
{
  sodium::key<ks1> key;

  BOOST_TEST(!sodium::is_zero(key));
  BOOST_TEST(key.size() == ks1);
  
  key.destroy(); // key.readwrite() is implicit here!

  BOOST_TEST(sodium::is_zero(key)); // must be all-zero now!
  BOOST_TEST(key.size() == ks1);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_empty_key )
{
  sodium::key<> key(false);  // default constructor: empty key with 0 bytes.

  // XXX: an empty key MUST be created with false, so that it
  // remains readwrite(). Calling it without arguments will
  // try a readonly(), which will crash the program with a
  // "no mapping at fault address" (because mprotect() on a
  // 0-page won't work).

  // We need a template specialization for Key<> that handles
  // this case separately...
  
  BOOST_TEST(key.size() == 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_move_ctor )
{
  sodium::key<ks1> key;                       // create random key
  auto key_data = key.data();

  sodium::key<ks1> key_copy {key};            // copy c'tor

  // it doesn't harm to remove access prior to move c'tor...
  key.noaccess();
  
  sodium::key<ks1> key_move {std::move(key)}; // move c'tor, key is now invalid
  auto key_move_data = key_move.data();
  
  // ... provided that we restored it to the target for more
  // testing further down.
  key_move.readonly();
  
  // we made a key_copy of key, so we can check that key_move
  // and key_copy are essentially the same key material
  
  BOOST_TEST(key_copy.size() == key_move.size());
  BOOST_TEST(sodium::compare(key_copy, key_move));
  BOOST_TEST((key_copy == key_move));

  // key itself must still be valid, but empty,
  // i.e. same as default-constructed with 0 bytes.
  BOOST_TEST(key.size()	== 0);

  // another way to test for empty keys:
  sodium::key<> key_empty(false);
  
  BOOST_TEST((key == key_empty));

  // XXX: even if ks1 != 0, key == key_empty after they have been
  // both emptied?
  
  // both key and key_move had the same representation in memory
  BOOST_TEST(key_data == key_move_data); // at same location
}

BOOST_AUTO_TEST_CASE( sodium_test_key_move_assignment )
{
  sodium::key<ks1> key;                  // create random key
  auto key_data = key.data();
  
  sodium::key<ks1> key_copy {key};       // copy c'tor
  sodium::key<ks1> key2;                 // create another random key
  auto key2_data = key2.data();
  
  // it doesn't harm to remove access prior to move assignemnt...
  key.noaccess();
  
  key2 = std::move(key); // move-assignement. key is now empty.
  auto key2_data_new = key2.data();

  // old key2 has been overwritten, and doesn't exist anymore.
  // new key2's underlying key_t keydata is at a completely new address.
  BOOST_TEST(key2_data_new != key2_data);
  
  // ... provided that we restored it for testing further down.
  key2.readonly();
  
  BOOST_TEST(key2.size() == key_copy.size()); // size has changed!
  BOOST_TEST(sodium::compare(key_copy, key2));
  BOOST_TEST((key_copy == key2));

  // key must still be valid, but empty,
  // i.e. same as default-constructed with 0 bytes.
  BOOST_TEST(key.size() == 0);

  // another way to test for empty keys:
  sodium::key<> key_empty(false);

  BOOST_TEST((key == key_empty)); // XXX

  // both key and key2 had the same key_type representation in memory
  BOOST_TEST(key_data == key2_data_new);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_std_move_doesnt_empty_key )
{
  sodium::key<ks1> key;

  BOOST_TEST(key.size() != 0);

  // merely calling std::move(key) doesn't empty the key of its
  // resources.
  
  // If we don't explicitely do something that invokes
  // a key move constructor as in
  // 
  //      key<SIZE> newKey {std::move(key)};
  //
  // or a key move assignment operator, as in
  // 
  //      key<SIZE> newKey = std::move(key);
  //
  // key itself will remain untouched and unharmed:
  
  BOOST_TEST((std::move(key)).size() != 0);
  BOOST_TEST(key.size() != 0);
}

BOOST_AUTO_TEST_CASE( sodium_test_key_select_copy_or_move )
{
  sodium::key<ks1> key;

  // interestingly, this doesn't generate a new key_t allocation:
  selectKey(key);            // calls selectKey(const key<ks1> &);

  // this doesn't either, but that was expected not to:
  selectKey(std::move(key)); // calls selectKey(key<ks1> &&);

  // after emptying key of its resources, selectKey(key<ks1> &&) has left
  // key as an empty shell:
  
  sodium::key<> key_empty(false);
  BOOST_TEST(key.size() == 0);

  BOOST_TEST((key == key_empty));

  // note that had selectKey(key<> &&) not explicitely pilfered the
  // resources from its key parameter, key here wouldn't be empty.
}

BOOST_AUTO_TEST_CASE(sodium_test_key_bytes_protected)
{
	sodium::key<ks2, sodium::bytes_protected> key;

	BOOST_TEST(!sodium::is_zero(key));
}

BOOST_AUTO_TEST_CASE(sodium_test_key_bytes_unprotected)
{
#if 0
	sodium::key<ks2, sodium::bytes> key; // should refuse to compile

	BOOST_TEST(!sodium::is_zero(key));
#endif
}

// NYI: add test cases for readwrite(), readonly() and noaccess()...

BOOST_AUTO_TEST_SUITE_END ()
