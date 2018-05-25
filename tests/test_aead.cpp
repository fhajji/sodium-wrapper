// test_aead.cpp -- Test sodium::aead
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
#define BOOST_TEST_MODULE sodium::aead Test
#include <boost/test/included/unit_test.hpp>

#include "aead.h"
#include <string>
#include <sodium.h>

template <typename BT=sodium::bytes,
	typename F=sodium::aead_xchacha20_poly1305_ietf>
bool
test_of_correctness(const std::string &header,
		    const std::string &plaintext,
		    std::size_t &ciphertext_size,
		    bool falsify_header = false,
		    bool falsify_ciphertext = false)
{
  sodium::aead<BT,F> sc;                // with random key
  sodium::aead<BT,F>::nonce_type nonce; // random nonce

  BT plainblob    {plaintext.cbegin(), plaintext.cend()};
  BT headerblob   {header.cbegin(), header.cend()};

  BT ciphertext = sc.encrypt(headerblob, plainblob, nonce);

  if (falsify_ciphertext && ciphertext.size() != 0)
    ++ciphertext[0];

  ciphertext_size = ciphertext.size();
  
  BT decrypted;

  // falsify the header AFTER encryption!
  if (falsify_header && headerblob.size() != 0)
    ++headerblob[0];
  
  try {
    decrypted = sc.decrypt(headerblob, ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    return false; // decryption failed;
  }

  return plainblob == decrypted;
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

// ---- *_1: BT=sodium::bytes, F=sodium::aead_xchacha20_poly1305_ietf ------------------------

BOOST_AUTO_TEST_CASE( sodium_aead_test_full_plaintext_full_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(test_of_correctness<>(header, plaintext, csize, false, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_full_plaintext_empty_header_1 )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(test_of_correctness<>(header, plaintext, csize, false, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_empty_plaintext_full_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_TEST(test_of_correctness<>(header, plaintext, csize, false, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_empty_plaintext_empty_header_1 )
{
  std::string header    {};
  std::string plaintext {};
  std::size_t csize;

  BOOST_TEST(test_of_correctness<>(header, plaintext, csize, false, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_empty_plaintext_falsify_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {};
  std::size_t csize;

  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, true, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_full_plaintext_falsify_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, true, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_falsify_plaintext_empty_header_1 )
{
  std::string header    {};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, false, true));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_falsify_plaintext_full_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, false, true));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_falsify_plaintext_falsify_header_1 )
{
  std::string header    {"the head"};
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, true, true));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);
}

BOOST_AUTO_TEST_CASE( sodium_aead_test_big_header_1 )
{
  std::string header(sodium::aead<>::MACSIZE * 200, 'A');
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  std::size_t csize;

  // The following test shows that the header is NOT included in
  // the ciphertext. Only the plaintext and the MAC are included
  // in the ciphertext, no matter how big the header may be.
  // It is the responsability of the user to transmit the header
  // separately from the ciphertext, i.e. to tag it along.
  
  BOOST_TEST(header.size() == sodium::aead<>::MACSIZE * 200);
  BOOST_TEST(test_of_correctness<>(header, plaintext, csize, false, false));
  BOOST_TEST(csize == plaintext.size() + sodium::aead<>::MACSIZE);

  // However, a modification of the header WILL be detected.
  // We modify only the 0-th byte right now, but a modification
  // SHOULD also be detected past MACSIZE bytes... (not tested)
  
  BOOST_TEST(! test_of_correctness<>(header, plaintext, csize, true, false));
}

// ---- *_2: BT = sodium::bytes_protected, F = sodium::aead_xchacha20_poly1305_ietf ---------

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_full_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_empty_header_2)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_full_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_empty_header_2)
{
	std::string header{};
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_falsify_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, true, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_falsify_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, true, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_empty_header_2)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, true));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_full_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, true));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_falsify_header_2)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, true, true));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_big_header_2)
{
	std::string header(sodium::aead<sodium::bytes_protected>::MACSIZE * 200, 'A');
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	// The following test shows that the header is NOT included in
	// the ciphertext. Only the plaintext and the MAC are included
	// in the ciphertext, no matter how big the header may be.
	// It is the responsability of the user to transmit the header
	// separately from the ciphertext, i.e. to tag it along.

	BOOST_TEST(header.size() == sodium::aead<sodium::bytes_protected>::MACSIZE * 200);
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, false, false));
	BOOST_TEST(csize == plaintext.size() + sodium::aead<sodium::bytes_protected>::MACSIZE);

	// However, a modification of the header WILL be detected.
	// We modify only the 0-th byte right now, but a modification
	// SHOULD also be detected past MACSIZE bytes... (not tested)

	BOOST_TEST(!test_of_correctness<sodium::bytes_protected>(header, plaintext, csize, true, false));
}

// ---- *_3: BT=sodium::bytes, F=sodium::aead_chacha20_poly1305 ------------------------

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_full_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_empty_header_3)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_full_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_empty_header_3)
{
	std::string header{};
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_falsify_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_falsify_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_empty_header_3)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_full_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_falsify_header_3)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, true, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_big_header_3)
{
	std::string header(sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE * 200, 'A');
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	// The following test shows that the header is NOT included in
	// the ciphertext. Only the plaintext and the MAC are included
	// in the ciphertext, no matter how big the header may be.
	// It is the responsability of the user to transmit the header
	// separately from the ciphertext, i.e. to tag it along.

	BOOST_TEST((header.size() == sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE * 200));
	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305>::MACSIZE));

	// However, a modification of the header WILL be detected.
	// We modify only the 0-th byte right now, but a modification
	// SHOULD also be detected past MACSIZE bytes... (not tested)

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305>(header, plaintext, csize, true, false)));
}

// ---- *_4: BT=sodium::bytes, F=sodium::aead_chacha20_poly1305_ietf -------------------

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_full_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_empty_header_4)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_full_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_empty_header_4)
{
	std::string header{};
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_falsify_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_falsify_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_empty_header_4)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_full_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_falsify_header_4)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, true, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_big_header_4)
{
	std::string header(sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE * 200, 'A');
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	// The following test shows that the header is NOT included in
	// the ciphertext. Only the plaintext and the MAC are included
	// in the ciphertext, no matter how big the header may be.
	// It is the responsability of the user to transmit the header
	// separately from the ciphertext, i.e. to tag it along.

	BOOST_TEST((header.size() == sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE * 200));
	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>::MACSIZE));

	// However, a modification of the header WILL be detected.
	// We modify only the 0-th byte right now, but a modification
	// SHOULD also be detected past MACSIZE bytes... (not tested)

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_chacha20_poly1305_ietf>(header, plaintext, csize, true, false)));
}

// ---- *_5: BT=sodium::bytes, F=sodium::aead_aesgcm -------------------

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_full_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_empty_header_5)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize, plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_full_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_empty_header_5)
{
	std::string header{};
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_falsify_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_falsify_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_empty_header_5)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_full_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_falsify_header_5)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, true, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_big_header_5)
{
	std::string header(sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE * 200, 'A');
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	// The following test shows that the header is NOT included in
	// the ciphertext. Only the plaintext and the MAC are included
	// in the ciphertext, no matter how big the header may be.
	// It is the responsability of the user to transmit the header
	// separately from the ciphertext, i.e. to tag it along.

	BOOST_TEST((header.size() == sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE * 200));
	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm>::MACSIZE));

	// However, a modification of the header WILL be detected.
	// We modify only the 0-th byte right now, but a modification
	// SHOULD also be detected past MACSIZE bytes... (not tested)

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm>(header, plaintext, csize, true, false)));
}

// ---- *_6: BT=sodium::bytes, F=sodium::aead_aesgcm_precomputed -------

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_full_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_empty_header_6)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize, plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_full_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_empty_header_6)
{
	std::string header{};
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_empty_plaintext_falsify_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{};
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_full_plaintext_falsify_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, true, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_empty_header_6)
{
	std::string header{};
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_full_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_falsify_plaintext_falsify_header_6)
{
	std::string header{ "the head" };
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, true, true)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));
}

BOOST_AUTO_TEST_CASE(sodium_aead_test_big_header_6)
{
	std::string header(sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE * 200, 'A');
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	std::size_t csize;

	// The following test shows that the header is NOT included in
	// the ciphertext. Only the plaintext and the MAC are included
	// in the ciphertext, no matter how big the header may be.
	// It is the responsability of the user to transmit the header
	// separately from the ciphertext, i.e. to tag it along.

	BOOST_TEST((header.size() == sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE * 200));
	BOOST_TEST((test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, false, false)));
	BOOST_TEST((csize == plaintext.size() + sodium::aead<sodium::bytes, sodium::aead_aesgcm_precomputed>::MACSIZE));

	// However, a modification of the header WILL be detected.
	// We modify only the 0-th byte right now, but a modification
	// SHOULD also be detected past MACSIZE bytes... (not tested)

	BOOST_TEST((!test_of_correctness<sodium::bytes, sodium::aead_aesgcm_precomputed>(header, plaintext, csize, true, false)));
}


// XXX TODO: Test that other types for F are being rejected at compile-time.

BOOST_AUTO_TEST_SUITE_END ()
