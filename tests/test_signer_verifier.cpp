// test_signer_verifier.cpp -- Test sodium::signer and sodium::verifier.
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
#define BOOST_TEST_MODULE sodium::signer_verifier Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "keypairsign.h"
#include "signer.h"
#include "verifier.h"
#include <algorithm>
#include <sodium.h>
#include <string>

using sodium::keypairsign;
using sodium::signer;
using sodium::verifier;
using bytes = sodium::bytes;
using chars = sodium::chars;
using bytes_protected = sodium::bytes_protected;

constexpr static std::size_t sigsize = signer<>::SIGNATURE_SIZE;

template<typename BT = bytes>
bool
test_of_correctness(const std::string& plaintext)
{
    keypairsign<> keypair_alice{};
    keypairsign<> keypair_bob{};

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. alice signs a message with her private key and sends it to bob
    signer<BT> s_alice{ keypair_alice.private_key() };

    BT plaintext_from_alice_to_bob_with_signature = s_alice.sign(plainblob);

    // 2. bob gets the public key from alice, and verifies the signature

    verifier<BT> v_bob{ keypair_alice.public_key() };

    BT message_to_bob_from_alice =
      v_bob.verify(plaintext_from_alice_to_bob_with_signature);

    // 3. if signature fails to verify, verify() would throw,
    // but we manually check anyway.

    BOOST_TEST(plainblob == message_to_bob_from_alice);

    // TURN AROUND

    // 4. bob echoes the messages back to alice, after signing it
    // himself with his private key.

    signer<BT> s_bob{ keypair_bob }; // using keypair_bob.private_key()

    BT plaintext_with_signature_from_bob_to_alice =
      s_bob.sign(message_to_bob_from_alice);

    // 5. alice attempts to verify that the message came from bob
    // using bob's public key.

    verifier<BT> v_alice{ keypair_bob.public_key() };

    BT plaintext_from_bob_to_alice =
      v_alice.verify(plaintext_with_signature_from_bob_to_alice);

    // 6. if signature verification fails, verify() would throw,
    // but we manually check anyway. We assume that bob echoed the
    // plaintext without modifying it.

    BOOST_TEST(plainblob == plaintext_from_bob_to_alice);

    return plainblob == plaintext_from_bob_to_alice;
}

template<typename BT = bytes>
bool
test_of_correctness_with_detached_signatures(const std::string& plaintext)
{
    keypairsign<> keypair_alice{};
    keypairsign<> keypair_bob{};

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. alice signs a message with her private key and sends it (plainblob)
    // and the signature (signature_from_alice) to bob.

    signer<BT> s_alice{ keypair_alice };

    bytes signature_from_alice = s_alice.sign_detached(plainblob);

    // 2. bob gets the public key from alice, and verifies that the message
    // and the signature match. Bob MUST ensure that the _pubkey_ from alice
    // is indeed from alice by other means (certificates, etc...).

    verifier<BT> v_bob{ keypair_alice.public_key() };

    BOOST_TEST(v_bob.verify_detached(
      plainblob, signature_from_alice /* hopefully from alice */));

    // 3. if signature fails to verify, verify_detach() would've returned
    // false and the test failed. If we come this far, the test succeeded.

    // TURN AROUND

    // 4. bob echoes the message back to alice, after signing it
    // himself with his private key. He sends both the message plainblob,
    // as well as the signature signature_from_bob to alice.

    signer<BT> s_bob{ keypair_bob.private_key() };

    bytes signature_from_bob = s_bob.sign_detached(plainblob);

    // 5. alice attempts to verify that the message came from bob
    // using the signature sent along with the message, and bob's public key.
    // Alice _MUST_ ensure that the _pubkey_ she's using does indeed belong
    // to bob by other means (e.g. certificates etc.).

    verifier<BT> v_alice{ keypair_bob.public_key() };

    BOOST_TEST(v_alice.verify_detached(plainblob, signature_from_bob));

    // 6. if signature verification fails, verify() would've returned false,
    // thus failing the test. Since we've came this far, the signature
    // verified, and the message came indeed from bob (and was not
    // modified en-route).

    return true;
}

template<typename BT = bytes>
bool
falsify_signature(const std::string& plaintext)
{
    keypairsign<> keypair_alice{};
    signer<BT> s{ keypair_alice };
    verifier<BT> v{ keypair_alice.public_key() };

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    BT signedtext = s.sign(plainblob);

    BOOST_TEST(signedtext.size() >= signer<BT>::SIGNATURE_SIZE);

    // falsify signature, which starts before the message proper
    ++signedtext[0];

    try {
        BT message_without_signature = v.verify(signedtext);
    } catch (std::exception& /* e */) {
        // verification failed as expected: test passed.
        return true;
    }

    // No expection caught: verification went ahead, eventhough we've
    // modified the signature. Test failed.

    return false;
}

template<typename BT = bytes>
bool
falsify_detached_signature(const std::string& plaintext)
{
    keypairsign<> keypair_alice{};
    signer<BT> s{ keypair_alice };
    verifier<BT> v{ keypair_alice.public_key() };

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes signature = s.sign_detached(plainblob);

    BOOST_TEST(signature.size() == sigsize);

    // falsify signature
    if (signature.size() != 0)
        ++signature[0];

    // inverse logic: if the signature verifies, the test failed
    return !v.verify_detached(plainblob, signature /* falsified */);
}

template<typename BT = bytes>
bool
falsify_signedtext(const std::string& plaintext)
{
    // before even bothering falsifying a signed plaintext, check that the
    // corresponding plaintext is not emptry!
    BOOST_CHECK_MESSAGE(!plaintext.empty(),
                        "Nothing to falsify, empty plaintext");

    keypairsign<> keypair_alice{};

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // sign to self
    BT signedtext = signer<BT>{ keypair_alice }.sign(plainblob);

    BOOST_TEST(signedtext.size() > signer<BT>::SIGNATURE_SIZE);

    // falsify plaintext, which starts just after signature
    ++signedtext[signer<BT>::SIGNATURE_SIZE];

    try {
        BT plaintext_without_signature =
          verifier<BT>{ keypair_alice.public_key() }.verify(signedtext);
    } catch (std::exception& /* e */) {
        // Exception caught as expected. Test passed.
        return true;
    }

    // Expection not caught: verification went ahead, eventhough we've
    // modified the signed (plain) text. Test failed.

    return false;
}

template<typename BT = bytes>
bool
falsify_plaintext(const std::string& plaintext)
{
    // before even bothering falsifying a plaintext, check that it is
    // not emptry!
    BOOST_CHECK_MESSAGE(!plaintext.empty(),
                        "Nothing to falsify, empty plaintext");

    keypairsign<> keypair_alice{};

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // sign to self
    bytes signature =
      signer<BT>{ keypair_alice.private_key() }.sign_detached(plainblob);

    BOOST_TEST(signature.size() == sigsize);

    // falsify plaintext
    ++plainblob[0];

    // inverse logic: if signature verifies, test fails!
    return !verifier<BT>{ keypair_alice.public_key() }.verify_detached(
      plainblob /* falsified */, signature);
}

template<typename BT = bytes>
bool
falsify_sender(const std::string& plaintext)
{
    keypairsign<> keypair_alice{}; // recipient
    keypairsign<> keypair_bob{};   // impersonated sender
    keypairsign<> keypair_oscar{}; // real sender

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. Oscar signs a plaintext that looks as if it was written by Bob.

    BT signedtext =
      signer<BT>(keypair_oscar.private_key()).sign(plainblob); // !!!

    // 2. Oscar prepends forged headers to the signedtext, making it appear
    // as if the message (= headers + signedtext) came indeed from Bob,
    // and sends the whole message, i.e. the envelope, to Alice.
    // Not shown here.

    // 3. Alice receives the message. Because of the envelope's headers,
    // she thinks the message came from Bob. Not shown here.

    // 4. Alice tries to verify the signature with Bob's public
    // key. This is the place where verification MUST fail.

    try {
        BT plaintext_without_signature =
          verifier<BT>(keypair_bob.public_key()).verify(signedtext); // !!!
        // if verification succeeded, Oscar was successful in impersonating Bob.
        // The test therefore failed!

        return false;
    } catch (std::exception& /* e */) {
        // verification failed; either because signedtext was modified
        // en route, or, more likely here, because keypair_bob.pubkey()
        // doesn't match keypair_oscar.privkey(). Oscar was not able to
        // impersonate Bob. Test was successful.

        return true;
    }

    // NOTREACHED
    return true;
}

template<typename BT = bytes>
bool
falsify_sender_detached(const std::string& plaintext)
{
    keypairsign<> keypair_alice{}; // recipient
    keypairsign<> keypair_bob{};   // impersonated sender
    keypairsign<> keypair_oscar{}; // real sender

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. Oscar signs a plaintext that looks as if it was written by Bob.

    bytes signature =
      signer<BT>(keypair_oscar.private_key()).sign_detached(plainblob); // !!!

    // 2. Oscar prepends forged headers to the plainblob and signature,
    // making it appear as if the message (= headers + signature +
    // plainblob) came indeed from Bob, and sends the whole message,
    // i.e. the envelope, to Alice.  Not shown here.

    // 3. Alice receives the message. Because of the envelope's headers,
    // she thinks the message came from Bob. Not shown here.

    // 4. Alice tries to verify the signature with Bob's public
    // key. This is the place where verification MUST fail.

    // Note: inverse logic!
    return !verifier<BT>(keypair_bob.public_key())
              .verify_detached(plainblob, signature);
}

struct SodiumFixture
{
    SodiumFixture()
    {
        BOOST_REQUIRE(sodium_init() != -1);
        // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
    }
    ~SodiumFixture()
    {
        // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
    }
};

BOOST_FIXTURE_TEST_SUITE(sodium_test_suite, SodiumFixture)

// --- 1. bytes -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(test_of_correctness<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_empty_plaintext_bytes)
{
    std::string plaintext{};
    BOOST_TEST(test_of_correctness<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_detached_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(test_of_correctness_with_detached_signatures<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_empty_plaintext_detached_bytes)
{
    std::string plaintext{};
    BOOST_TEST(test_of_correctness_with_detached_signatures<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_bytes)
{
    keypairsign<> keypair_alice{};
    signer<> s_alice{ keypair_alice };
    verifier<> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes signedtext = s_alice.sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<>::SIGNATURE_SIZE);

    bytes message_without_signature = v_alice.verify(signedtext);

    // if the signedtext was modified, or came from another
    // source, verification would have thrown. But we manually check anyway.

    BOOST_TEST(plainblob == message_without_signature);
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_detached_bytes)
{
    keypairsign<> keypair_alice{};
    signer<> s_alice{ keypair_alice.private_key() };
    verifier<> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes signature = s_alice.sign_detached(plainblob);

    BOOST_TEST(signature.size() == sigsize);

    BOOST_TEST(v_alice.verify_detached(plainblob, signature));

    // if the signedtext was modified, or came from another source,
    // verification would have returned false and test would have
    // failed.  but here, the test was successful.
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_detect_wrong_sender_fulltext_bytes)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_detect_wrong_sender_empty_text_bytes)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_fulltext_bytes)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender_detached<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_empty_text_bytes)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender_detached<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signedtext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signedtext<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_plaintext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_plaintext<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signature_fulltext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signature<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signature_empty_bytes)
{
    std::string plaintext{};

    BOOST_TEST(falsify_signature<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_falsify_detached_signature_fulltext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_detached_signature<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_detached_signature_empty_bytes)
{
    std::string plaintext{};

    BOOST_TEST(falsify_detached_signature<bytes>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_plaintext_remains_plaintext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    keypairsign<> keypair_alice{};

    bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

    // sign to self
    bytes signedtext = signer<>(keypair_alice).sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<>::SIGNATURE_SIZE);

    // The signed text starts with signer::SIGNATURE_SIZE bytes of
    // signature, followed by the (hopefully) unchanged bytes of the
    // plaintext.
    BOOST_TEST(std::equal(plainblob.data(),
                          plainblob.data() + plainblob.size(),
                          signedtext.data() + signer<>::SIGNATURE_SIZE));

    // We double-check in both directions, to make sure there are no
    // spurious bytes remaining.
    BOOST_TEST(std::equal(signedtext.data() + signer<>::SIGNATURE_SIZE,
                          signedtext.data() + signedtext.size(),
                          plainblob.data()));
}

// --- 2. chars -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(test_of_correctness<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_empty_plaintext_chars)
{
    std::string plaintext{};
    BOOST_TEST(test_of_correctness<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_detached_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(test_of_correctness_with_detached_signatures<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_empty_plaintext_detached_chars)
{
    std::string plaintext{};
    BOOST_TEST(test_of_correctness_with_detached_signatures<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_chars)
{
    keypairsign<> keypair_alice{};
    signer<chars> s_alice{ keypair_alice };
    verifier<chars> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    chars signedtext = s_alice.sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<chars>::SIGNATURE_SIZE);

    chars message_without_signature = v_alice.verify(signedtext);

    // if the signedtext was modified, or came from another
    // source, verification would have thrown. But we manually check anyway.

    BOOST_TEST(plainblob == message_without_signature);
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_detached_chars)
{
    keypairsign<> keypair_alice{};
    signer<chars> s_alice{ keypair_alice.private_key() };
    verifier<chars> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes signature = s_alice.sign_detached(plainblob);

    BOOST_TEST(signature.size() == sigsize);

    BOOST_TEST(v_alice.verify_detached(plainblob, signature));

    // if the signedtext was modified, or came from another source,
    // verification would have returned false and test would have
    // failed.  but here, the test was successful.
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_detect_wrong_sender_fulltext_chars)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_detect_wrong_sender_empty_text_chars)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_fulltext_chars)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender_detached<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_empty_text_chars)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender_detached<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signedtext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signedtext<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_plaintext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_plaintext<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signature_fulltext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signature<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signature_empty_chars)
{
    std::string plaintext{};

    BOOST_TEST(falsify_signature<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_falsify_detached_signature_fulltext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_detached_signature<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_detached_signature_empty_chars)
{
    std::string plaintext{};

    BOOST_TEST(falsify_detached_signature<chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_plaintext_remains_plaintext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    keypairsign<> keypair_alice{};

    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    // sign to self
    chars signedtext = signer<chars>(keypair_alice).sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<chars>::SIGNATURE_SIZE);

    // The signed text starts with signer<chars>::SIGNATURE_SIZE bytes of
    // signature, followed by the (hopefully) unchanged bytes of the
    // plaintext.
    BOOST_TEST(std::equal(plainblob.data(),
                          plainblob.data() + plainblob.size(),
                          signedtext.data() + signer<chars>::SIGNATURE_SIZE));

    // We double-check in both directions, to make sure there are no
    // spurious bytes remaining.
    BOOST_TEST(std::equal(signedtext.data() + signer<chars>::SIGNATURE_SIZE,
                          signedtext.data() + signedtext.size(),
                          plainblob.data()));
}

// --- 3. bytes_protected -------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(test_of_correctness<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_empty_plaintext_bytes_protected)
{
    std::string plaintext{};
    BOOST_TEST(test_of_correctness<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_full_plaintext_detached_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_TEST(
      test_of_correctness_with_detached_signatures<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_empty_plaintext_detached_bytes_protected)
{
    std::string plaintext{};
    BOOST_TEST(
      test_of_correctness_with_detached_signatures<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_bytes_protected)
{
    keypairsign<> keypair_alice{};
    signer<bytes_protected> s_alice{ keypair_alice };
    verifier<bytes_protected> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes_protected signedtext = s_alice.sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<bytes_protected>::SIGNATURE_SIZE);

    bytes_protected message_without_signature = v_alice.verify(signedtext);

    // if the signedtext was modified, or came from another
    // source, verification would have thrown. But we manually check anyway.

    BOOST_TEST(plainblob == message_without_signature);
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_sign_to_self_detached_bytes_protected)
{
    keypairsign<> keypair_alice{};
    signer<bytes_protected> s_alice{ keypair_alice.private_key() };
    verifier<bytes_protected> v_alice{ keypair_alice.public_key() };

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

    bytes signature = s_alice.sign_detached(plainblob);

    BOOST_TEST(signature.size() == sigsize);

    BOOST_TEST(v_alice.verify_detached(plainblob, signature));

    // if the signedtext was modified, or came from another source,
    // verification would have returned false and test would have
    // failed.  but here, the test was successful.
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_fulltext_bytes_protected)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_empty_text_bytes_protected)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_fulltext_bytes_protected)
{
    std::string plaintext{ "Hi Alice, this is Bob!" };

    BOOST_TEST(falsify_sender_detached<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_detect_wrong_sender_detached_empty_text_bytes_protected)
{
    std::string plaintext{};

    BOOST_TEST(falsify_sender_detached<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signedtext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signedtext<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_plaintext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_plaintext<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_falsify_signature_fulltext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_signature<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_signor_test_falsify_signature_empty_bytes_protected)
{
    std::string plaintext{};

    BOOST_TEST(falsify_signature<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_falsify_detached_signature_fulltext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_TEST(falsify_detached_signature<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_falsify_detached_signature_empty_bytes_protected)
{
    std::string plaintext{};

    BOOST_TEST(falsify_detached_signature<bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_signor_test_plaintext_remains_plaintext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    keypairsign<> keypair_alice{};

    bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

    // sign to self
    bytes_protected signedtext =
      signer<bytes_protected>(keypair_alice).sign(plainblob);

    BOOST_TEST(signedtext.size() ==
               plainblob.size() + signer<bytes_protected>::SIGNATURE_SIZE);

    // The signed text starts with signer<bytes_protected>::SIGNATURE_SIZE bytes
    // of signature, followed by the (hopefully) unchanged bytes of the
    // plaintext.
    BOOST_TEST(
      std::equal(plainblob.data(),
                 plainblob.data() + plainblob.size(),
                 signedtext.data() + signer<bytes_protected>::SIGNATURE_SIZE));

    // We double-check in both directions, to make sure there are no
    // spurious bytes remaining.
    BOOST_TEST(
      std::equal(signedtext.data() + signer<bytes_protected>::SIGNATURE_SIZE,
                 signedtext.data() + signedtext.size(),
                 plainblob.data()));
}

BOOST_AUTO_TEST_SUITE_END()
