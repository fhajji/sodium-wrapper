// test_StreamSignorPK.cpp -- Test sodium::{StreamSignorPK,StreamVerifierPK}
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
#define BOOST_TEST_MODULE sodium::StreamSignorPK_StreamVerifierPK Test
#include <boost/test/included/unit_test.hpp>

#include "streamsignorpk.h"
#include "streamverifierpk.h"
#include "keypairsign.h"
#include <string>
// #include <algorithm>
#include <sstream>
#include <sodium.h>

using sodium::KeyPairSign;
using sodium::StreamSignorPK;
using sodium::StreamVerifierPK;
using bytes = sodium::bytes;

constexpr static std::size_t sigsize   = StreamSignorPK::SIGNATURE_SIZE;
constexpr static std::size_t blocksize = 8;

bool
test_of_correctness(const std::string &plaintext)
{
  KeyPairSign       keypair_alice     {};
  KeyPairSign       keypair_bob       {};
  StreamSignorPK    sc_signor_alice   (keypair_alice.privkey(), blocksize);
  StreamVerifierPK  sc_verifier_alice (keypair_alice.pubkey(), blocksize);
  StreamSignorPK    sc_signor_bob     (keypair_bob.privkey(), blocksize);
  StreamVerifierPK  sc_verifier_bob   (keypair_bob.pubkey(), blocksize);
  
  // 1. alice signs a message with her private key and sends it to bob
  std::istringstream istr_plaintext_alice_to_bob(plaintext);
  bytes signature_from_alice_to_bob =
    sc_signor_alice.sign(istr_plaintext_alice_to_bob);

  // 2. bob gets the plaintext and signature from alice and verifies the
  // signature using alice's public key
  std::istringstream istr_plaintext_bob_from_alice(plaintext);
  BOOST_CHECK(sc_verifier_alice.verify(istr_plaintext_bob_from_alice,
				       signature_from_alice_to_bob));
  
  // 3. if signature fails to verify, verify() would've returned false
  // and the test would have failed. If we came this far, the test
  // succeeded.  

  // TURN AROUND
  
  // 4. bob echoes the messages back to alice, after signing it
  // himself with his private key. Bob sends plaintext and
  // signature_from_bob_to_alice to alice.
  std::istringstream istr_plaintext_bob_to_alice(plaintext);
  bytes signature_from_bob_to_alice =
    sc_signor_bob.sign(istr_plaintext_bob_to_alice);
  
  // 5. alice attempts to verify that the message came from bob
  // using bob's public key and the signature sent by the person
  // who claims to be bob.
  std::istringstream istr_plaintext_alice_from_bob(plaintext);
  BOOST_CHECK(sc_verifier_bob.verify(istr_plaintext_alice_from_bob,
				     signature_from_bob_to_alice));
  
  // 6. if signature verification fails, verify() would've returned
  // false (or would've thrown, if streams were faulty). If we came this
  // far, the test was successful.

  return true;
}

bool
falsify_signature(const std::string &plaintext)
{
  KeyPairSign      keypair_alice {};
  StreamSignorPK   sc_signor     {keypair_alice, blocksize};
  StreamVerifierPK sc_verifier   {keypair_alice, blocksize};

  std::istringstream istr(plaintext);
  bytes signature = sc_signor.sign(istr);

  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  // falsify signature
  BOOST_CHECK(signature.size() != 0);
  ++signature[0];

  // negative logic: signature MUST NOT verify for test to succeed.
  std::istringstream istr_received(plaintext);
  BOOST_CHECK(! sc_verifier.verify(istr_received, signature));

  return true;
}

bool
falsify_plaintext(const std::string &plaintext)
{
  // before even bothering falsifying a signed plaintext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");

  KeyPairSign        keypair_alice {};
  StreamSignorPK     sc_signor     {keypair_alice.privkey(), blocksize};
  StreamVerifierPK   sc_verifier   {keypair_alice.pubkey(),  blocksize};
  
  std::istringstream istr(plaintext);
  
  // sign to self
  bytes signature = sc_signor.sign(istr);

  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  // falsify plaintext
  std::string falsifiedtext(plaintext);
  ++falsifiedtext[0];

  // inverse logic: verifying the signature on the falsified text
  // MUST NOT succeed for the test to succeed.
  std::istringstream istr_falsified(falsifiedtext);
  BOOST_CHECK(! sc_verifier.verify(istr_falsified, signature));

  return true;
}

bool
falsify_sender(const std::string &plaintext)
{
  KeyPairSign        keypair_alice {}; // recipient
  KeyPairSign        keypair_bob   {}; // impersonated sender
  KeyPairSign        keypair_oscar {}; // real sender

  StreamSignorPK     sc_oscar      {keypair_oscar.privkey(), blocksize};
  StreamVerifierPK   sc_bob        {keypair_bob.pubkey(), blocksize};

  std::istringstream istr(plaintext);
  
  // 1. Oscar signs a plaintext that looks as if it was written by Bob.
  
  bytes signature = sc_oscar.sign(istr);

  // 2. Oscar prepends forged headers to the plaintext, making it
  // appear as if the message (= headers + signature + plaintext) came
  // indeed from Bob, and sends the whole message, i.e. the envelope,
  // to Alice.  Not shown here.

  // 3. Alice receives the message. Because of the envelope's headers,
  // she thinks the message came from Bob. Not shown here.
  
  // 4. Alice tries to verify the signature with Bob's public
  // key. This is the place where verification MUST fail.

  std::istringstream istr_received(plaintext);
  BOOST_CHECK(! sc_bob.verify(istr_received, signature));

  return true;
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

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_sign_to_self )
{
  KeyPairSign        keypair_alice {};
  StreamSignorPK     sc_signor     {keypair_alice.privkey(), blocksize};
  StreamVerifierPK   sc_verifier   {keypair_alice.pubkey(),  blocksize};

  std::string        plaintext {"the quick brown fox jumps over the lazy dog"};
  std::istringstream istr(plaintext);

  bytes signature = sc_signor.sign(istr);

  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  std::istringstream istr_received(plaintext);
  
  BOOST_CHECK(sc_verifier.verify(istr_received, signature));
  
  // if the plaintext was modified, or came from another
  // source, verification would have returned false, thus failing
  // the test. Further more, verification would've thrown, if the
  // stream failed. If we came this far, the test succeeded.
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_detect_wrong_sender_fulltext )
{
  std::string plaintext {"Hi Alice, this is Bob!"};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_detect_wrong_sender_empty_text)
{
  std::string plaintext {};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_falsify_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_plaintext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_falsify_signature_fulltext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_falsify_signature_empty )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_multiple_sign_verify )
{
  KeyPairSign      keypair_alice {};
  StreamSignorPK   sc_signor     (keypair_alice.privkey(), blocksize);
  StreamVerifierPK sc_verifier   (keypair_alice.pubkey(),  blocksize);
  
  std::string plaintext1 {"the quick brown fox jumps over the lazy dog"};
  std::string plaintext2 {"CPE1704TKS"};

  std::istringstream istr1(plaintext1);
  std::istringstream istr2(plaintext2);

  bytes signature1 = sc_signor.sign(istr1);
  bytes signature2 = sc_signor.sign(istr2); // should reset state internally

  std::istringstream istr1_received(plaintext1);
  std::istringstream istr2_received(plaintext2); 
  
  BOOST_CHECK(sc_verifier.verify(istr1_received, signature1));
  BOOST_CHECK(sc_verifier.verify(istr2_received, signature2)); // ditto
}

BOOST_AUTO_TEST_CASE( sodium_streamsignorpk_test_small_plaintext )
{
  KeyPairSign      keypair_alice {};
  StreamSignorPK   sc_signor     (keypair_alice.privkey(), 128);
  StreamVerifierPK sc_verifier   (keypair_alice.pubkey(),  128);
  
  std::string plaintext {"CPE1704TKS"}; // Note: plaintext.size() < 128

  std::istringstream istr(plaintext);

  bytes signature = sc_signor.sign(istr);

  std::istringstream istr_received(plaintext);
  
  BOOST_CHECK(sc_verifier.verify(istr_received, signature));
}

BOOST_AUTO_TEST_SUITE_END ()
