// test_CryptorMultiPK.cpp -- Test sodium::CryptorMultiPK
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

// To see some timing output, run this test like this:
//   ./test_CryptorMultiPK --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::CryptorMultiPK Test
#include <boost/test/included/unit_test.hpp>

#include "box.h"
#include "cryptormultipk.h"
#include "keypair.h"

#include <string>
#include <sstream>
#include <chrono>

#include <sodium.h>

using namespace std::chrono;

using sodium::keypair;
using sodium::box;
using sodium::CryptorMultiPK;

using bytes = sodium::bytes;

bool
test_of_correctness(const std::string &plaintext)
{
  keypair<> keypair_alice;
  keypair<> keypair_bob;
  CryptorMultiPK::nonce_type nonce;

  CryptorMultiPK sc_alice(keypair_alice.private_key(),
				   keypair_bob.public_key());
  CryptorMultiPK sc_bob(keypair_bob.private_key(),
				   keypair_alice.public_key());

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice uses the shared key with bob to encrypt and sign
  //    a message:
  
  bytes ciphertext_from_alice_to_bob =
    sc_alice.encrypt(plainblob, nonce);

  // 2. bob uses the shared key with alice to decrypt the message
  //    and verify alice's signature:
  
  bytes decrypted_by_bob_from_alice =
    sc_bob.decrypt(ciphertext_from_alice_to_bob, nonce);

  // 3. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway.
  
  BOOST_CHECK(plainblob == decrypted_by_bob_from_alice);

  // 4. bob echoes the messages back to alice. Remember to increment nonce!

  nonce.increment(); // IMPORTANT! before calling encrypt() again

  bytes ciphertext_from_bob_to_alice =
    sc_bob.encrypt(decrypted_by_bob_from_alice, nonce);

  // 5. alice attempts to decrypt again (also with the incremented nonce)
  bytes decrypted_by_alice_from_bob =
    sc_alice.decrypt(ciphertext_from_bob_to_alice, nonce);

  // 6. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway. We assume that bob echoed the
  // plaintext without modifying it.

  BOOST_CHECK(plainblob == decrypted_by_alice_from_bob);
  
  return plainblob == decrypted_by_alice_from_bob;
}

bool
falsify_mac(const std::string &plaintext)
{
  keypair<> keypair_alice;
  CryptorMultiPK::nonce_type nonce;
  CryptorMultiPK sc(keypair_alice);
  
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() >= CryptorMultiPK::MACSIZE);

  // falsify mac, which starts before the ciphertext proper
  ++ciphertext[0];

  try {
    bytes decrypted = sc.decrypt(ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    // decryption failed as expected: test passed.
    return true;
  }

  // No expection caught: decryption went ahead, eventhough we've
  // modified the mac. Test failed.

  return false;
}

bool
falsify_ciphertext(const std::string &plaintext)
{
  // before even bothering falsifying a ciphertext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");
  
  keypair<> keypair_alice;
  CryptorMultiPK::nonce_type nonce;
  CryptorMultiPK sc(keypair_alice);
  
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  bytes ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() > CryptorMultiPK::MACSIZE);

  // falsify ciphertext, which starts just after MAC
  ++ciphertext[CryptorMultiPK::MACSIZE];

  try {
    bytes decrypted = sc.decrypt(ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    // Exception caught as expected. Test passed.
    return true;
  }

  // Expection not caught: decryption went ahead, eventhough we've
  // modified the ciphertext. Test failed.

  return false;
}

bool
falsify_sender(const std::string &plaintext)
{
  keypair<> keypair_alice; // recipient
  keypair<> keypair_bob;   // impersonated sender
  keypair<> keypair_oscar; // real sender
  CryptorMultiPK::nonce_type nonce;

  CryptorMultiPK             sc_alice(keypair_alice.private_key(),
				      keypair_bob.public_key());
  CryptorMultiPK             sc_bob  (keypair_bob.private_key(),
				      keypair_alice.public_key());
  CryptorMultiPK             sc_oscar(keypair_oscar.private_key(),
				      keypair_alice.public_key());

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Oscar encrypts a plaintext that looks as if it was written by Bob
  // with Alice's public key, and signs it with his own private key.
  
  bytes ciphertext = sc_oscar.encrypt(plainblob, nonce);

  // 2. Oscar prepends forged headers to the ciphertext, making it appear
  // as if the message (= headers + ciphertext) came indeed from Bob,
  // and sends the whole message, i.e. the envelope, to Alice.
  // Not shown here.

  // 3. Alice receives the message. Because of the envelope's headers,
  // she thinks the message came from Bob. Not shown here.
  
  // 4. Alice decrypts the message with her own private key. She
  // tries to verify the signature with Bob's public key. This is
  // the place where decryption MUST fail.

  try {
    bytes decrypted = sc_alice.decrypt(ciphertext, nonce);

    // if decryption succeeded, Oscar was successful in impersonating Bob.
    // The test therefore failed!

    return false;
  }
  catch (std::exception & /* e */) {
    // decryption failed; either because ciphertext was modified
    // en route, or, more likely here, because keypair_bob.pubkey()
    // doesn't match keypair_oscar.privkey(). Oscar was not able to
    // impersonate Bob. Test was successful.

    return true;
  }

  // NOTREACHED
  return true;
}

bool
destroy_shared_key_then_encrypt(const bytes &plaintext)
{
  keypair<> keypair_alice {};
  CryptorMultiPK::nonce_type nonce {};
  CryptorMultiPK sc_alice(keypair_alice);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    bytes ciphertext = sc_alice.encrypt(plaintext, nonce);

    // 2. encryption succeeded despite destroyed shared key.
    // test failed.
    return false;
  }
  catch (std::exception & /* e */) {
    // 3. encryption failed as expected because of destroyed shared key.
    // test succeeded.
    return true;
  }

  // NOTREACHED
  return true;
}

bool
destroy_shared_key_then_decrypt(const bytes &ciphertext,
				const keypair<> &keypair,
				const CryptorMultiPK::nonce_type &nonce)
{
  CryptorMultiPK sc_alice(keypair);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    bytes decrypted = sc_alice.decrypt(ciphertext, nonce);

    // 2. decryption succeeded despite destroyed shared key.
    // test failed.
    return false;
  }
  catch (std::exception & /* e */) {
    // 3. decryption failed as expected, probably because of
    // destroyed shared key. test succeeded.
    return true;
  }

  // NOTREACHED
  return true;
}

void
time_encrypt(const unsigned long nr_of_messages)
{
  keypair<>                  keypair_alice   {};
  CryptorMultiPK::nonce_type nonce_multi     {};
  box<>::nonce_type      nonce_single    {};
  box<>                  sc_single_alice {};
  CryptorMultiPK             sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  bytes ciphertext_multi (plaintext.size() + CryptorMultiPK::MACSIZE);
  bytes ciphertext_single(plaintext.size() + box<>::MACSIZE);

  std::ostringstream os;
  
  // 1. time encrypting nr_of_messages with CryptorMultiPK
  auto t00 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    ciphertext_multi = sc_multi_alice.encrypt(plainblob,
					      nonce_multi);
    nonce_multi.increment();
  }
  auto t01 = system_clock::now();
  auto tmulti = duration_cast<milliseconds>(t01-t00).count();

  os << "Encrypting " << nr_of_messages << " messages (multi ): "
     << tmulti << " milliseconds." << std::endl;
  
  // 2. time encrypting nr_of_messages with box
  auto t10 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    ciphertext_single = sc_single_alice.encrypt(plainblob,
						keypair_alice,
						nonce_single);
    nonce_single.increment();
  }
  auto t11 = system_clock::now();
  auto tsingle = duration_cast<milliseconds>(t11-t10).count();

  os << "Encrypting " << nr_of_messages << " messages (single): "
     << tsingle << " milliseconds." << std::endl;

  BOOST_TEST_MESSAGE(os.str());
  
  BOOST_CHECK_MESSAGE(tmulti < tsingle,
		      "sodium::CryptorMultiPK::encrypt() slower than sodium::box::encrypt()");
}

void
time_decrypt(const unsigned long nr_of_messages)
{
  keypair<>                  keypair_alice   {};
  box<>::nonce_type      nonce_single    {};
  CryptorMultiPK::nonce_type nonce_multi     {};
  box<>                  sc_single_alice {};
  CryptorMultiPK             sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  bytes decrypted_multi (plaintext.size());
  bytes decrypted_single(plaintext.size());

  // 0. encrypt once the plaintext without timing
  bytes ciphertext_multi  = sc_multi_alice.encrypt(plainblob, nonce_multi);
  bytes ciphertext_single = sc_single_alice.encrypt(plainblob,
					      keypair_alice,
					      nonce_single);
  
  std::ostringstream os;

  // 1. time decrypting nr_of_messages with CryptorMultiPK
  auto t00 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    decrypted_multi = sc_multi_alice.decrypt(ciphertext_multi,
					     nonce_multi);
    // since we decrypt over and over the same ciphertext message,
    // we don't nonce_multi.increment() here.
  }
  auto t01 = system_clock::now();
  auto tmulti = duration_cast<milliseconds>(t01-t00).count();

  os << "Decrypting " << nr_of_messages << " messages (multi ): "
     << tmulti << " milliseconds." << std::endl;
  
  // 2. time decrypting nr_of_messages with box
  auto t10 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    decrypted_single = sc_single_alice.decrypt(ciphertext_single,
					       keypair_alice,
					       nonce_single);
    // since we decrypt over and over the same ciphtertext message,
    // we don't nonce_single.increment() here.
  }
  auto t11 = system_clock::now();
  auto tsingle = duration_cast<milliseconds>(t11-t10).count();

  os << "Decrypting " << nr_of_messages << " messages (single): "
     << tsingle << " milliseconds." << std::endl;

  BOOST_TEST_MESSAGE(os.str());
  
  BOOST_CHECK_MESSAGE(tmulti < tsingle,
		      "Sodium::CryptorMultiPK::decrypt() slower than Sodium::box::decrypt()");
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

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptomultipk_test_encrypt_to_self )
{
  keypair<>                  keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes ciphertext = sc_alice.encrypt(plainblob, nonce);

  BOOST_CHECK_EQUAL(ciphertext.size(),
		    plainblob.size() + CryptorMultiPK::MACSIZE);

  bytes decrypted = sc_alice.decrypt(ciphertext, nonce);

  // if the ciphertext (with MAC) was modified, or came from another
  // source, decryption would have thrown. But we manually check anyway.

  BOOST_CHECK(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_detect_wrong_sender_fulltext )
{
  std::string plaintext {"Hi Alice, this is Bob!"};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_detect_wrong_sender_empty_text)
{
  std::string plaintext {};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_falsify_ciphertext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_ciphertext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_falsify_mac_fulltext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_mac(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_falsify_mac_empty )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_mac(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_destroysharedkey_encrypt )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  BOOST_CHECK(destroy_shared_key_then_encrypt(plainblob));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_destroysharedkey_decrypt )
{
  keypair<>                  keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  bytes ciphertext = sc_alice.encrypt(plainblob, nonce);

  BOOST_CHECK(destroy_shared_key_then_decrypt(ciphertext,
					      keypair_alice,
					      nonce));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_time_multimessages_encrypt )
{
  time_encrypt(1000);
  time_encrypt(10000);
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_time_multimessages_decrypt )
{
  time_decrypt(1000);
  time_decrypt(10000);
}

BOOST_AUTO_TEST_SUITE_END ()
