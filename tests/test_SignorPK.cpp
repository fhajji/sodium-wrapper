// test_SignorPK.cpp -- Test sodium::SignorPK
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
#define BOOST_TEST_MODULE sodium::SignorPK Test
#include <boost/test/included/unit_test.hpp>

#include "signorpk.h"
#include "keypairsign.h"
#include <string>
#include <algorithm>
#include <sodium.h>

using sodium::KeyPairSign;
using sodium::SignorPK;
using bytes = sodium::bytes;

constexpr static std::size_t sigsize = SignorPK::SIGNATURE_SIZE;

bool
test_of_correctness(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};
  KeyPairSign keypair_bob   {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice signs a message with her private key and sends it to bob
  
  bytes plaintext_from_alice_to_bob_with_signature =
    sc.sign(plainblob,
	    keypair_alice.privkey());

  // 2. bob gets the public key from alice, and verifies the signature
  
  bytes message_to_bob_from_alice =
    sc.verify(plaintext_from_alice_to_bob_with_signature,
	      keypair_alice.pubkey());

  // 3. if signature fails to verify, verify() would throw,
  // but we manually check anyway.
  
  BOOST_CHECK(plainblob == message_to_bob_from_alice);

  // TURN AROUND
  
  // 4. bob echoes the messages back to alice, after signing it
  // himself with his private key.

  bytes plaintext_with_signature_from_bob_to_alice =
    sc.sign(message_to_bob_from_alice,
	    keypair_bob.privkey());

  // 5. alice attempts to verify that the message came from bob
  // using bob's public key.
  bytes plaintext_from_bob_to_alice =
    sc.verify(plaintext_with_signature_from_bob_to_alice,
	      keypair_bob.pubkey());

  // 6. if signature verification fails, verify() would throw,
  // but we manually check anyway. We assume that bob echoed the
  // plaintext without modifying it.

  BOOST_CHECK(plainblob == plaintext_from_bob_to_alice);
  
  return plainblob == plaintext_from_bob_to_alice;
}

bool
test_of_correctness_with_detached_signatures(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};
  KeyPairSign keypair_bob   {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice signs a message with her private key and sends it (plainblob)
  // and the signature (signature_from_alice) to bob.
  
  bytes signature_from_alice =
    sc.sign_detached(plainblob,
		     keypair_alice.privkey());

  // 2. bob gets the public key from alice, and verifies that the message
  // and the signature match. Bob MUST ensure that the _pubkey_ from alice
  // is indeed from alice by other means (certificates, etc...).
  
  BOOST_CHECK(sc.verify_detached(plainblob,
				 signature_from_alice, // hopefully from alice
				 keypair_alice.pubkey()));
  
  // 3. if signature fails to verify, verify_detach() would've returned
  // false and the test failed. If we come this far, the test succeeded.

  // TURN AROUND
  
  // 4. bob echoes the message back to alice, after signing it
  // himself with his private key. He sends both the message plainblob,
  // as well as the signature signature_from_bob to alice.

  bytes signature_from_bob =
    sc.sign_detached(plainblob,
		     keypair_bob.privkey());

  // 5. alice attempts to verify that the message came from bob
  // using the signature sent along with the message, and bob's public key.
  // Alice _MUST_ ensure that the _pubkey_ she's using does indeed belong
  // to bob by other means (e.g. certificates etc.).
  
  BOOST_CHECK(sc.verify_detached(plainblob,
				 signature_from_bob,
				 keypair_bob.pubkey()));

  // 6. if signature verification fails, verify() would've returned false,
  // thus failing the test. Since we've came this far, the signature
  // verified, and the message came indeed from bob (and was not
  // modified en-route).

  return true;
}

bool
falsify_signature(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes signedtext  = sc.sign(plainblob, keypair_alice);

  BOOST_CHECK(signedtext.size() >= SignorPK::SIGNATURE_SIZE);

  // falsify signature, which starts before the message proper
  ++signedtext[0];

  try {
    bytes message_without_signature = sc.verify(signedtext,
						 keypair_alice);
  }
  catch (std::exception & /* e */) {
    // verification failed as expected: test passed.
    return true;
  }

  // No expection caught: verification went ahead, eventhough we've
  // modified the signature. Test failed.

  return false;
}

bool
falsify_detached_signature(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes signature = sc.sign_detached(plainblob, keypair_alice);
  
  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  // falsify signature
  if (signature.size() != 0)
    ++signature[0];

  // inverse logic: if the signature verifies, the test failed
  return ! sc.verify_detached(plainblob,
			      signature, // falsified
			      keypair_alice);
}

bool
falsify_signedtext(const std::string &plaintext)
{
  // before even bothering falsifying a signed plaintext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");
  
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // sign to self
  bytes signedtext = sc.sign(plainblob, keypair_alice);

  BOOST_CHECK(signedtext.size() > SignorPK::SIGNATURE_SIZE);

  // falsify plaintext, which starts just after signature
  ++signedtext[SignorPK::SIGNATURE_SIZE];

  try {
    bytes plaintext_without_signature = sc.verify(signedtext,
						   keypair_alice);
  }
  catch (std::exception & /* e */) {
    // Exception caught as expected. Test passed.
    return true;
  }

  // Expection not caught: verification went ahead, eventhough we've
  // modified the signed (plain) text. Test failed.

  return false;
}

bool
falsify_plaintext(const std::string &plaintext)
{
  // before even bothering falsifying a plaintext, check that it is
  // not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");
  
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // sign to self
  bytes signature = sc.sign_detached(plainblob, keypair_alice);

  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  // falsify plaintext
  ++plainblob[0];

  // inverse logic: if signature verifies, test fails!
  return ! sc.verify_detached(plainblob, // falsified
			      signature,
			      keypair_alice);
}

bool
falsify_sender(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {}; // recipient
  KeyPairSign keypair_bob   {}; // impersonated sender
  KeyPairSign keypair_oscar {}; // real sender

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Oscar signs a plaintext that looks as if it was written by Bob.
  
  bytes signedtext = sc.sign(plainblob, keypair_oscar.privkey()); // !!!

  // 2. Oscar prepends forged headers to the signedtext, making it appear
  // as if the message (= headers + signedtext) came indeed from Bob,
  // and sends the whole message, i.e. the envelope, to Alice.
  // Not shown here.

  // 3. Alice receives the message. Because of the envelope's headers,
  // she thinks the message came from Bob. Not shown here.
  
  // 4. Alice tries to verify the signature with Bob's public
  // key. This is the place where verification MUST fail.

  try {
    bytes plaintext_without_signature = sc.verify(signedtext,
						   keypair_bob.pubkey()); // !!!
    // if verification succeeded, Oscar was successful in impersonating Bob.
    // The test therefore failed!

    return false;
  }
  catch (std::exception & /* e */) {
    // verification failed; either because signedtext was modified
    // en route, or, more likely here, because keypair_bob.pubkey()
    // doesn't match keypair_oscar.privkey(). Oscar was not able to
    // impersonate Bob. Test was successful.

    return true;
  }

  // NOTREACHED
  return true;
}

bool
falsify_sender_detached(const std::string &plaintext)
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {}; // recipient
  KeyPairSign keypair_bob   {}; // impersonated sender
  KeyPairSign keypair_oscar {}; // real sender

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Oscar signs a plaintext that looks as if it was written by Bob.
  
  bytes signature = sc.sign_detached(plainblob,
					     keypair_oscar.privkey()); // !!!

  // 2. Oscar prepends forged headers to the plainblob and signature,
  // making it appear as if the message (= headers + signature +
  // plainblob) came indeed from Bob, and sends the whole message,
  // i.e. the envelope, to Alice.  Not shown here.

  // 3. Alice receives the message. Because of the envelope's headers,
  // she thinks the message came from Bob. Not shown here.
  
  // 4. Alice tries to verify the signature with Bob's public
  // key. This is the place where verification MUST fail.

  // Note: inverse logic!
  return ! sc.verify_detached(plainblob,
			      signature,
			      keypair_bob.pubkey());
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

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_full_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_empty_plaintext )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_full_plaintext_detached )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_CHECK(test_of_correctness_with_detached_signatures(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_empty_plaintext_detached )
{
  std::string plaintext {};
  BOOST_CHECK(test_of_correctness_with_detached_signatures(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_sign_to_self )
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes signedtext = sc.sign(plainblob, keypair_alice);

  BOOST_CHECK_EQUAL(signedtext.size(),
		    plainblob.size() + SignorPK::SIGNATURE_SIZE);

  bytes message_without_signature = sc.verify(signedtext,
					       keypair_alice);

  // if the signedtext was modified, or came from another
  // source, verification would have thrown. But we manually check anyway.

  BOOST_CHECK(plainblob == message_without_signature);
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_sign_to_self_detached )
{
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes signature = sc.sign_detached(plainblob,
				      keypair_alice);

  BOOST_CHECK_EQUAL(signature.size(), sigsize);

  BOOST_CHECK(sc.verify_detached(plainblob,
				 signature,
				 keypair_alice));

  // if the signedtext was modified, or came from another source,
  // verification would have returned false and test would have
  // failed.  but here, the test was successful.
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_detect_wrong_sender_fulltext )
{
  std::string plaintext {"Hi Alice, this is Bob!"};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_detect_wrong_sender_empty_text)
{
  std::string plaintext {};

  BOOST_CHECK(falsify_sender(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_detect_wrong_sender_detached_fulltext )
{
  std::string plaintext {"Hi Alice, this is Bob!"};

  BOOST_CHECK(falsify_sender_detached(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_detect_wrong_sender_detached_empty_text)
{
  std::string plaintext {};

  BOOST_CHECK(falsify_sender_detached(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_signedtext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_signedtext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_plaintext(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_signature_fulltext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_signature_empty )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_detached_signature_fulltext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_CHECK(falsify_detached_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_falsify_detached_signature_empty )
{
  std::string plaintext {};

  BOOST_CHECK(falsify_detached_signature(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_signorpk_test_plaintext_remains_plaintext )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  
  SignorPK    sc            {};
  KeyPairSign keypair_alice {};

  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // sign to self
  bytes signedtext = sc.sign(plainblob, keypair_alice);

  BOOST_CHECK_EQUAL(signedtext.size(),
		    plainblob.size() + SignorPK::SIGNATURE_SIZE);

  // The signed text starts with SignorPK::SIGNATURE_SIZE bytes of
  // signature, followed by the (hopefully) unchanged bytes of the
  // plaintext.
  BOOST_CHECK(std::equal(plainblob.data(), plainblob.data() + plainblob.size(),
			 signedtext.data() + SignorPK::SIGNATURE_SIZE));

  // We double-check in both directions, to make sure there are no
  // spurious bytes remaining.
  BOOST_CHECK(std::equal(signedtext.data() + SignorPK::SIGNATURE_SIZE,
			 signedtext.data() + signedtext.size(),
			 plainblob.data()));
}

BOOST_AUTO_TEST_SUITE_END ()
