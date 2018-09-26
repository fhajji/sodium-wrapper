// test_box_seal.cpp -- Test sealed boxes from sodium::box_seal
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
#define BOOST_TEST_MODULE sodium::box_seal Test
#include <boost/test/included/unit_test.hpp>

#include "box_seal.h"
#include "keypair.h"
#include <sodium.h>
#include <string>

using sodium::box_seal;
using sodium::keypair;
using bytes = sodium::bytes;

template<typename BT = bytes>
bool
test_of_correctness(const std::string& plaintext)
{
    box_seal<BT> sb{};
    keypair<BT> keypair_alice{};
    keypair<BT> keypair_bob{};

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. alice gets the public key from bob, and sends him a message

    BT ciphertext_from_alice_to_bob =
      sb.encrypt(plainblob, keypair_bob.public_key());

    // 2. bob decrypts the message

    BT decrypted_by_bob_from_someone = sb.decrypt(ciphertext_from_alice_to_bob,
                                                  keypair_bob.private_key(),
                                                  keypair_bob.public_key());

    // 3. if decryption (MAC or signature) fails, decrypt() would throw,
    // but we manually check anyway.

    BOOST_CHECK(plainblob == decrypted_by_bob_from_someone);

    // TURN AROUND

    // 4. bob echoes the messages back to alice.

    BT ciphertext_from_bob_to_alice =
      sb.encrypt(decrypted_by_bob_from_someone, keypair_alice);

    // 5. alice attempts to decrypt again
    BT decrypted_by_alice_from_someone =
      sb.decrypt(ciphertext_from_bob_to_alice, keypair_alice);

    // 6. if decryption (MAC or signature) fails, decrypt() would throw,
    // but we manually check anyway. We assume that bob echoed the
    // plaintext without modifying it.

    BOOST_CHECK(plainblob == decrypted_by_alice_from_someone);

    return plainblob == decrypted_by_alice_from_someone;
}

template<typename BT = bytes>
bool
falsify_seal(const std::string& plaintext)
{
    box_seal<BT> sb;
    keypair<BT> keypair_alice;

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // encrypt to self
    BT ciphertext = sb.encrypt(plainblob, keypair_alice);

    BOOST_CHECK(ciphertext.size() >= box_seal<BT>::SEALSIZE);

    // falsify seal, which starts before the ciphertext proper
    ++ciphertext[0];

    try {
        BT decrypted = sb.decrypt(ciphertext, keypair_alice);
    } catch (std::exception& /* e */) {
        // decryption failed as expected: test passed.
        return true;
    }

    // No expection caught: decryption went ahead, eventhough we've
    // modified the seal. Test failed.

    return false;
}

template<typename BT = bytes>
bool
falsify_ciphertext(const std::string& plaintext)
{
    // before even bothering falsifying a ciphertext, check that the
    // corresponding plaintext is not emptry!
    BOOST_CHECK_MESSAGE(!plaintext.empty(),
                        "Nothing to falsify, empty plaintext");

    box_seal<BT> sb;
    keypair<BT> keypair_alice;

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // encrypt to self
    BT ciphertext = sb.encrypt(plainblob, keypair_alice);

    BOOST_CHECK(ciphertext.size() > box_seal<BT>::SEALSIZE);

    // falsify ciphertext _box_, which starts just after MAC (XXX)
    ++ciphertext[box_seal<BT>::SEALSIZE];

    try {
        BT decrypted = sb.decrypt(ciphertext, keypair_alice);
    } catch (std::exception& /* e */) {
        // Exception caught as expected. Test passed.
        return true;
    }

    // Expection not caught: decryption went ahead, eventhough we've
    // modified the ciphertext (or mac). Test failed.

    return false;
}

template<typename BT = bytes>
bool
falsify_recipient(const std::string& plaintext)
{
    box_seal<BT> sb{};
    keypair<BT> keypair_alice{}; // sender
    keypair<BT> keypair_bob{};   // intended recipient
    keypair<BT> keypair_oscar{}; // real recipient

    BT plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. Alice encrypts a plaintext intended to be sent to bob,
    // with bob's public key.

    BT ciphertext = sb.encrypt(plainblob, keypair_bob);

    // 2. Alice sends the sealed ciphertext to bob. Not shown here.

    // 3. Oscar intercepts the message, and tries to decrypt it with
    // his own private key. This is the place where decryption MUST fail.

    try {
        BT decrypted = sb.decrypt(ciphertext, keypair_oscar);

        // if decryption succeeded, Oscar was successful in impersonating Bob.
        // The test therefore failed!

        return false;
    } catch (std::exception& /* e */) {
        // decryption failed; either because ciphertext was modified
        // en route, or, more likely here, because keypair_bob
        // doesn't match keypair_oscar. Oscar was not able to
        // impersonate Bob. Test was successful.

        return true;
    }

    // NOTREACHED
    return true;
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

// 1. sodium::bytes -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_full_plaintext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_CHECK(test_of_correctness<>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_empty_plaintext_bytes)
{
    std::string plaintext{};
    BOOST_CHECK(test_of_correctness<>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_encrypt_to_self_bytes)
{
    box_seal<> sb{};
    keypair<> keypair_alice{};

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

    // encrypt to self
    bytes ciphertext = sb.encrypt(plainblob, keypair_alice);

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      plainblob.size() + box_seal<>::SEALSIZE);

    bytes decrypted = sb.decrypt(ciphertext, keypair_alice);

    // if the ciphertext (with MAC) was modified, or came from another
    // source, decryption would have thrown. But we manually check anyway.

    BOOST_CHECK(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_fulltext_bytes)
{
    std::string plaintext{ "Hi Bob, this is your secret admirer!" };

    BOOST_CHECK(falsify_recipient<>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_empty_text_bytes)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_recipient<>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_ciphertext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_ciphertext<>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_seal_fulltext_bytes)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_seal<>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_seal_empty_bytes)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_seal<>(plaintext));
}

// 2. sodium::bytes_protected ----------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_full_plaintext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_CHECK(test_of_correctness<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_empty_plaintext_bytes_protected)
{
    std::string plaintext{};
    BOOST_CHECK(test_of_correctness<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_encrypt_to_self_bytes_protected)
{
    box_seal<sodium::bytes_protected> sb{};
    keypair<sodium::bytes_protected> keypair_alice{};

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

    // encrypt to self
    sodium::bytes_protected ciphertext = sb.encrypt(plainblob, keypair_alice);

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      plainblob.size() +
                        box_seal<sodium::bytes_protected>::SEALSIZE);

    sodium::bytes_protected decrypted = sb.decrypt(ciphertext, keypair_alice);

    // if the ciphertext (with MAC) was modified, or came from another
    // source, decryption would have thrown. But we manually check anyway.

    BOOST_CHECK(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_fulltext_bytes_protected)
{
    std::string plaintext{ "Hi Bob, this is your secret admirer!" };

    BOOST_CHECK(falsify_recipient<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_empty_text_bytes_protected)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_recipient<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_ciphertext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_ciphertext<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_falsify_seal_fulltext_bytes_protected)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_seal<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_seal_empty_bytes_protected)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_seal<sodium::bytes_protected>(plaintext));
}

// 3. sodium::chars -----------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_full_plaintext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    BOOST_CHECK(test_of_correctness<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_empty_plaintext_chars)
{
    std::string plaintext{};
    BOOST_CHECK(test_of_correctness<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_encrypt_to_self_chars)
{
    box_seal<sodium::chars> sb{};
    keypair<sodium::chars> keypair_alice{};

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    // encrypt to self
    sodium::chars ciphertext = sb.encrypt(plainblob, keypair_alice);

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      plainblob.size() + box_seal<sodium::chars>::SEALSIZE);

    sodium::chars decrypted = sb.decrypt(ciphertext, keypair_alice);

    // if the ciphertext (with MAC) was modified, or came from another
    // source, decryption would have thrown. But we manually check anyway.

    BOOST_CHECK(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_fulltext_chars)
{
    std::string plaintext{ "Hi Bob, this is your secret admirer!" };

    BOOST_CHECK(falsify_recipient<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(
  sodium_sealedbox_test_detect_wrong_recipient_empty_text_chars)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_recipient<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_ciphertext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_ciphertext<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_seal_fulltext_chars)
{
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    BOOST_CHECK(falsify_seal<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_sealedbox_test_falsify_seal_empty_bytes_chars)
{
    std::string plaintext{};

    BOOST_CHECK(falsify_seal<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_SUITE_END()
