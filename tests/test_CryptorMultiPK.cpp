// test_CryptorMultiPK.cpp -- Test Sodium::CryptorMultiPK
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

// To see some timing output, run this test like this:
//   ./test_CryptorMultiPK --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Sodium::CryptorMultiPK Test
#include <boost/test/included/unit_test.hpp>

#include <sodium.h>
#include "cryptorpk.h"
#include "cryptormultipk.h"
#include "keypair.h"

#include <string>
#include <sstream>
#include <chrono>

using namespace std::chrono;

using Sodium::KeyPair;
using Sodium::CryptorPK;
using Sodium::CryptorMultiPK;

using data_t = Sodium::data_t;

bool
test_of_correctness(const std::string &plaintext)
{
  KeyPair                    keypair_alice {};
  KeyPair                    keypair_bob   {};
  CryptorMultiPK::nonce_type nonce         {};

  CryptorMultiPK          sc_alice(keypair_alice.privkey(),
				   keypair_bob.pubkey());
  CryptorMultiPK          sc_bob(keypair_bob.privkey(),
				 keypair_alice.pubkey());

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice uses the shared key with bob to encrypt and sign
  //    a message:
  
  data_t ciphertext_from_alice_to_bob =
    sc_alice.encrypt(plainblob, nonce);

  // 2. bob uses the shared key with alice to decrypt the message
  //    and verify alice's signature:
  
  data_t decrypted_by_bob_from_alice =
    sc_bob.decrypt(ciphertext_from_alice_to_bob, nonce);

  // 3. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway.
  
  BOOST_CHECK(plainblob == decrypted_by_bob_from_alice);

  // 4. bob echoes the messages back to alice. Remember to increment nonce!

  nonce.increment(); // IMPORTANT! before calling encrypt() again

  data_t ciphertext_from_bob_to_alice =
    sc_bob.encrypt(decrypted_by_bob_from_alice, nonce);

  // 5. alice attempts to decrypt again (also with the incremented nonce)
  data_t decrypted_by_alice_from_bob =
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
  KeyPair                    keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc(keypair_alice);
  
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  data_t ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() >= CryptorMultiPK::MACSIZE);

  // falsify mac, which starts before the ciphertext proper
  ++ciphertext[0];

  try {
    data_t decrypted = sc.decrypt(ciphertext, nonce);
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
  
  KeyPair                    keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc(keypair_alice);
  
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  data_t ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_CHECK(ciphertext.size() > CryptorMultiPK::MACSIZE);

  // falsify ciphertext, which starts just after MAC
  ++ciphertext[CryptorMultiPK::MACSIZE];

  try {
    data_t decrypted = sc.decrypt(ciphertext, nonce);
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
  KeyPair                    keypair_alice {}; // recipient
  KeyPair                    keypair_bob   {}; // impersonated sender
  KeyPair                    keypair_oscar {}; // real sender
  CryptorMultiPK::nonce_type nonce    {};

  CryptorMultiPK             sc_alice(keypair_alice.privkey(),
				      keypair_bob.pubkey());
  CryptorMultiPK             sc_bob  (keypair_bob.privkey(),
				      keypair_alice.pubkey());
  CryptorMultiPK             sc_oscar(keypair_oscar.privkey(),
				      keypair_alice.pubkey());

  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Oscar encrypts a plaintext that looks as if it was written by Bob
  // with Alice's public key, and signs it with his own private key.
  
  data_t ciphertext = sc_oscar.encrypt(plainblob, nonce);

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
    data_t decrypted = sc_alice.decrypt(ciphertext, nonce);

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
destroy_shared_key_then_encrypt(const data_t &plaintext)
{
  KeyPair                    keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc_alice(keypair_alice);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    data_t ciphertext = sc_alice.encrypt(plaintext, nonce);

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
destroy_shared_key_then_decrypt(const data_t                     &ciphertext,
				const KeyPair                    &keypair,
				const CryptorMultiPK::nonce_type &nonce)
{
  CryptorMultiPK sc_alice(keypair);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    data_t decrypted = sc_alice.decrypt(ciphertext, nonce);

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
  KeyPair                    keypair_alice   {};
  CryptorMultiPK::nonce_type nonce_multi     {};
  CryptorPK::nonce_type      nonce_single    {};
  CryptorPK                  sc_single_alice {};
  CryptorMultiPK             sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  data_t ciphertext_multi (plaintext.size() + CryptorMultiPK::MACSIZE);
  data_t ciphertext_single(plaintext.size() + CryptorPK::MACSIZE);

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
  
  // 2. time encrypting nr_of_messages with CryptorPK
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
		      "Sodium::CryptorMultiPK::encrypt() slower than Sodium::CryptorPK::encrypt()");
}

void
time_decrypt(const unsigned long nr_of_messages)
{
  KeyPair                    keypair_alice   {};
  CryptorPK::nonce_type      nonce_single    {};
  CryptorMultiPK::nonce_type nonce_multi     {};
  CryptorPK                  sc_single_alice {};
  CryptorMultiPK             sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  data_t decrypted_multi (plaintext.size());
  data_t decrypted_single(plaintext.size());

  // 0. encrypt once the plaintext without timing
  data_t ciphertext_multi  = sc_multi_alice.encrypt(plainblob, nonce_multi);
  data_t ciphertext_single = sc_single_alice.encrypt(plainblob,
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
  
  // 2. time decrypting nr_of_messages with CryptorPK
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
		      "Sodium::CryptorMultiPK::decrypt() slower than Sodium::CryptorPK::decrypt()");
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

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

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
  KeyPair                    keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  data_t ciphertext = sc_alice.encrypt(plainblob, nonce);

  BOOST_CHECK_EQUAL(ciphertext.size(),
		    plainblob.size() + CryptorMultiPK::MACSIZE);

  data_t decrypted = sc_alice.decrypt(ciphertext, nonce);

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
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  BOOST_CHECK(destroy_shared_key_then_encrypt(plainblob));
}

BOOST_AUTO_TEST_CASE( sodium_cryptormultipk_test_destroysharedkey_decrypt )
{
  KeyPair                    keypair_alice {};
  CryptorMultiPK::nonce_type nonce         {};
  CryptorMultiPK             sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  data_t ciphertext = sc_alice.encrypt(plainblob, nonce);

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

BOOST_AUTO_TEST_SUITE_END ();
