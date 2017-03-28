// test_SealedBox.cpp -- Test Sodium::SealedBox
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
#define BOOST_TEST_MODULE Sodium::SealedBox Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "sealedbox.h"
#include "keypair.h"
#include <string>

using Sodium::KeyPair;
using Sodium::SealedBox;
using data_t = Sodium::data_t;

bool
test_of_correctness(const std::string &plaintext)
{
  SealedBox               sb            {};
  KeyPair                 keypair_alice {};
  KeyPair                 keypair_bob   {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice gets the public key from bob, and sends him a message
  
  data_t ciphertext_from_alice_to_bob =
    sb.encrypt(plainblob,
	       keypair_bob.pubkey());

  // 2. bob decrypts the message
  
  data_t decrypted_by_bob_from_someone =
    sb.decrypt(ciphertext_from_alice_to_bob,
	       keypair_bob.privkey(),
	       keypair_bob.pubkey());

  // 3. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway.
  
  BOOST_CHECK(plainblob == decrypted_by_bob_from_someone);

  // TURN AROUND
  
  // 4. bob echoes the messages back to alice.

  data_t ciphertext_from_bob_to_alice =
    sb.encrypt(decrypted_by_bob_from_someone,
	       keypair_alice);

  // 5. alice attempts to decrypt again
  data_t decrypted_by_alice_from_someone =
    sb.decrypt(ciphertext_from_bob_to_alice,
	       keypair_alice);

  // 6. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway. We assume that bob echoed the
  // plaintext without modifying it.

  BOOST_CHECK(plainblob == decrypted_by_alice_from_someone);
  
  return plainblob == decrypted_by_alice_from_someone;
}

bool
falsify_seal(const std::string &plaintext)
{
  SealedBox               sb            {};
  KeyPair                 keypair_alice {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  data_t ciphertext = sb.encrypt(plainblob,
				 keypair_alice);

  BOOST_CHECK(ciphertext.size() >= SealedBox::SEALSIZE);

  // falsify seal, which starts before the ciphertext proper
  ++ciphertext[0];

  try {
    data_t decrypted = sb.decrypt(ciphertext,
				  keypair_alice);
  }
  catch (std::exception &e) {
    // decryption failed as expected: test passed.
    return true;
  }

  // No expection caught: decryption went ahead, eventhough we've
  // modified the seal. Test failed.

  return false;
}

bool
falsify_ciphertext(const std::string &plaintext)
{
  // before even bothering falsifying a ciphertext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");
  
  SealedBox               sb            {};
  KeyPair                 keypair_alice {};

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  data_t ciphertext = sb.encrypt(plainblob,
				 keypair_alice);

  BOOST_CHECK(ciphertext.size() > SealedBox::SEALSIZE);

  // falsify ciphertext _box_, which starts just after MAC (XXX)
  ++ciphertext[SealedBox::SEALSIZE];

  try {
    data_t decrypted = sb.decrypt(ciphertext,
				  keypair_alice);
  }
  catch (std::exception &e) {
    // Exception caught as expected. Test passed.
    return true;
  }

  // Expection not caught: decryption went ahead, eventhough we've
  // modified the ciphertext (or mac). Test failed.

  return false;
}

bool
falsify_recipient(const std::string &plaintext)
{
  SealedBox               sb            {};
  KeyPair                 keypair_alice {}; // sender
  KeyPair                 keypair_bob   {}; // intended recipient
  KeyPair                 keypair_oscar {}; // real recipient

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Alice encrypts a plaintext intended to be sent to bob,
  // with bob's public key.
  
  data_t ciphertext = sb.encrypt(plainblob,
				 keypair_bob);

  // 2. Alice sends the sealed ciphertext to bob. Not shown here.

  // 3. Oscar intercepts the message, and tries to decrypt it with
  // his own private key. This is the place where decryption MUST fail.
  
  try {
    data_t decrypted = sb.decrypt(ciphertext,
				  keypair_oscar);

    // if decryption succeeded, Oscar was successful in impersonating Bob.
    // The test therefore failed!

    return false;
  }
  catch (std::exception &e) {
    // decryption failed; either because ciphertext was modified
    // en route, or, more likely here, because keypair_bob
    // doesn't match keypair_oscar. Oscar was not able to
    // impersonate Bob. Test was successful.

    return true;
  }

  // NOTREACHED
  return true;
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

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_encrypt_to_self )
{
  SealedBox               sb            {};
  KeyPair                 keypair_alice {};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  data_t ciphertext = sb.encrypt(plainblob,
				 keypair_alice);

  BOOST_CHECK_EQUAL(ciphertext.size(),
		    plainblob.size() + SealedBox::SEALSIZE);

  data_t decrypted = sb.decrypt(ciphertext,
				keypair_alice);

  // if the ciphertext (with MAC) was modified, or came from another
  // source, decryption would have thrown. But we manually check anyway.

  BOOST_CHECK(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_detect_wrong_recipient_fulltext )
{
  std::string plaintext {"Hi Bob, this is your secret admirer!"};

  BOOST_CHECK(falsify_recipient(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_detect_wrong_recipient_empty_text)
{
  std::string plaintext {};

  BOOST_CHECK(falsify_recipient(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_falsify_ciphertext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_ciphertext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_falsify_seal_fulltext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_seal(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_sealedbox_test_falsify_seal_empty )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_seal(plaintext));
}

BOOST_AUTO_TEST_SUITE_END ();
