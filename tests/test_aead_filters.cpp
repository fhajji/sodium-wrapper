// test_aead_filters.cpp -- Test sodium::aead_{encrypt,decrypt}_filter
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
#define BOOST_TEST_MODULE sodium::aead_filters Test
#include <boost/test/included/unit_test.hpp>

#include "aead_decrypt_filter.h"
#include "aead_encrypt_filter.h"
#include "common.h"

#include <algorithm>
#include <stdexcept>
#include <string>

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using sodium::aead_decrypt_filter;
using sodium::aead_encrypt_filter;
using chars = sodium::chars;
using aead = sodium::aead<chars>; // NOT bytes!

namespace io = boost::iostreams;

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

bool
test_of_correctness_combined_output_filter(const std::string& header,
                                           const std::string& plaintext)
{
    aead_encrypt_filter::key_type key;     // Create a random key
    aead_encrypt_filter::nonce_type nonce; // Create a random nonce
    aead crypt{ std::move(key) };

    chars headerblob{ header.cbegin(), header.cend() };

    aead_encrypt_filter encrypt_filter{ crypt,
                                        nonce,
                                        headerblob }; // COPY crypt to...
    aead_decrypt_filter decrypt_filter{ std::move(crypt),
                                        nonce,
                                        headerblob }; // ... reuse here.

    chars plainblob{ plaintext.cbegin(), plaintext.cend() };
    chars decrypted(2 * plaintext.size()); // because of both writes below

    try {
        io::array_sink sink{ decrypted.data(), decrypted.size() };
        io::filtering_ostream os{};
        os.push(encrypt_filter); // first encrypt
        os.push(decrypt_filter); // then decrypt again
        os.push(sink);           // and store result in sink/derypted.

        os.write(plainblob.data(), plainblob.size());
        os.write(plainblob.data(),
                 plainblob.size()); // simulate multiple writes
        os.flush();

        os.pop();
    } catch (std::exception& /* e */) {
        // decryption failed for some reason

#ifndef NDEBUG
        std::cerr
          << "test_of_correctness_combined_output_filter(): decryption failed"
          << std::endl;
#endif // ! NDEBUG

        return false;
    }

    // sink (i.e. decrypted) has been hopefully filled with decrypted text

    // because we've sent plainblob TWICE with os.write() to the sink,
    // decrypted == (plainblob || plainblob).

    return std::equal(decrypted.cbegin(),
                      decrypted.cbegin() + plaintext.size(),
                      plainblob.cbegin()) &&
           std::equal(decrypted.cbegin() + plaintext.size(),
                      decrypted.cend(),
                      plainblob.cbegin());
}

bool
test_of_correctness_combined_input_filter(const std::string& header,
                                          const std::string& plaintext)
{
    chars headerblob{ header.cbegin(), header.cend() };
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };
    chars plainblob2{ plainblob };
    std::copy(
      plainblob.cbegin(),
      plainblob.cend(),
      std::back_inserter(plainblob2)); // plainblob2 = (plainblob || plainblob)

    aead_encrypt_filter::key_type key;     // Create a random key
    aead_encrypt_filter::nonce_type nonce; // Create a random nonce

    aead crypt{ std::move(key) };

    aead_encrypt_filter encrypt_filter{ crypt, nonce, headerblob };
    aead_decrypt_filter decrypt_filter{ std::move(crypt), nonce, headerblob };

    chars decrypted(2 * plaintext.size()); // because of plainblob2 above

    io::array_source source{ plainblob2.data(), plainblob2.size() };
    io::filtering_istream is{};

    is.push(decrypt_filter); // ... then decrypt again
    is.push(encrypt_filter); // first encrypt...
    is.push(source);         // data from source / plainblob2

    // fetch decrypted text from the filter chain:
    is.read(decrypted.data(), decrypted.size());

    is.pop();

    BOOST_CHECK(is); // decrypting encrypted text MUST succeed!

    // decrypted has been hopefully filled with decrypted text

    // because we've sent plainblob2,
    // decrypted == (plainblob || plainblob).

    return decrypted == plainblob2;
}

bool
test_of_correctness_output_filter(const std::string& header,
                                  const std::string& plaintext,
                                  bool falsify_header = false,
                                  bool falsify_ciphertext = false,
                                  bool falsify_mac = false,
                                  bool falsify_key = false,
                                  bool falsify_nonce = false)
{
    chars headerblob{ header.cbegin(), header.cend() };
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    // create a falsified header (only for non-empty headers)
    chars headerblob2 = headerblob;
    if (!headerblob2.empty())
        ++headerblob2[0];

    // 1. encrypt plaintext into ciphertext

    aead_encrypt_filter::key_type key;      // Create a random key
    aead_decrypt_filter::key_type key2;     // Create another random key
    aead_encrypt_filter::nonce_type nonce;  // Create a random nonce
    aead_decrypt_filter::nonce_type nonce2; // Create another random nonce

    aead crypt{ std::move(key) };
    aead crypt2{ std::move(key2) };

    aead_encrypt_filter encrypt_filter{ crypt, nonce, headerblob };
    aead_decrypt_filter decrypt_filter{
        (falsify_key ? std::move(crypt2) : std::move(crypt)),
        (falsify_nonce ? nonce2 : nonce),
        (falsify_header ? headerblob2 : headerblob)
    };

    chars ciphertext(aead_encrypt_filter::MACSIZE + plaintext.size());

    io::array_sink sink1{ ciphertext.data(), ciphertext.size() };
    io::filtering_ostream os1{};
    os1.push(encrypt_filter); // encrypt
    os1.push(sink1);          // then store result in sink/ciphertext.

    os1.write(plainblob.data(), plainblob.size());

    os1.pop();

    // sink1 (i.e. ciphertext) contains (MAC || ciphertext)

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      aead_encrypt_filter::MACSIZE + plainblob.size());

    if (!plaintext.empty() && falsify_ciphertext) {
        // ciphertext is of the form: (MAC || actual_ciphertext)
        ++ciphertext[aead_encrypt_filter::MACSIZE]; // falsify ciphertext
    }

    if (falsify_mac) {
        // ciphertext is of the form: (MAC || actual_ciphertext)
        ++ciphertext[0]; // falsify MAC
    }

    // 2. now, (attempt to) decrypt ciphertext into decrypted:

    chars decrypted(ciphertext.size() - aead_decrypt_filter::MACSIZE);
    try {
        io::array_sink sink2{ decrypted.data(), decrypted.size() };
        io::filtering_ostream os2{};
        os2.push(decrypt_filter); // (attempt to) decrypt
        os2.push(sink2);          // then store result in sink/ciphertext.

        os2.write(ciphertext.data(), ciphertext.size());

        os2.pop();

        // sink2 (i.e. decrypted) has been hopefully filled with decrypted text

        BOOST_CHECK_EQUAL(decrypted.size(), plainblob.size());
    } catch (std::exception& /* e */) {
        // decryption failed. This is expected if and only if we falsified
        // the ciphertext OR we falsified the MAC
        // OR we falsified the key
        // OR we falsified the nonce
        // OR we falsified the header (or any combination of those)

#ifndef NDEBUG
        std::cerr << "test_of_correctness_output_filter(): decryption failed"
                  << std::endl;
#endif // ! NDEBUG

        return falsify_header || falsify_ciphertext || falsify_mac ||
               falsify_key || falsify_nonce;
    }

    // decryption succeeded and plainblob == decrypted if and only if
    // we don't falsify the ciphertext nor the MAC,
    // nor the key nor the nonce
    // not the header.

#ifndef NDEBUG
    std::cerr << "test_of_correctness_output_filter(): decryption succeeded"
              << std::endl;
#endif // ! NDEBUG

    return !falsify_ciphertext && !falsify_mac && !falsify_key &&
           !falsify_nonce && !falsify_header && (plainblob == decrypted);
}

bool
test_of_correctness_input_filter(const std::string& header,
                                 const std::string& plaintext,
                                 bool falsify_header = false,
                                 bool falsify_ciphertext = false,
                                 bool falsify_mac = false,
                                 bool falsify_key = false,
                                 bool falsify_nonce = false)
{
    chars headerblob{ header.cbegin(), header.cend() };

    // create a falsified header (only for non-empty headers)
    chars headerblob2 = headerblob;
    if (!headerblob2.empty())
        ++headerblob2[0];

    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    // 1. encrypt plaintext into ciphertext

    aead crypt;  // create a cryptor with a random key
    aead crypt2; // create a cryptor with another random key
    aead_encrypt_filter::nonce_type nonce;  // Create a random nonce
    aead_decrypt_filter::nonce_type nonce2; // Create another random nonce

    aead_encrypt_filter encrypt_filter{ crypt, nonce, headerblob };
    aead_decrypt_filter decrypt_filter{
        (falsify_key ? std::move(crypt2) : std::move(crypt)),
        (falsify_nonce ? nonce2 : nonce),
        (falsify_header ? headerblob2 : headerblob)
    };

    chars ciphertext(aead_encrypt_filter::MACSIZE + plaintext.size());

    io::array_source source1{ plainblob.data(), plainblob.size() };
    io::filtering_istream is1{};
    is1.push(encrypt_filter); // encrypt data...
    is1.push(source1);        // from source1 / plainblob.

    // fetch ciphertext by reading into variable ciphertext
    is1.read(ciphertext.data(), ciphertext.size());

    is1.pop();

    // variable ciphertext contains (MAC || ciphertext)

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      aead_encrypt_filter::MACSIZE + plainblob.size());

#ifndef NDEBUG
    std::string ciphertext_string{ ciphertext.cbegin(), ciphertext.cend() };
    std::cerr << "t-o-c-i-f() ciphertext={" << ciphertext_string
              << "} size=" << ciphertext.size() << std::endl;
#endif // ! NDEBUG

    // 2. falsify ciphertext if asked

    if (!plaintext.empty() && falsify_ciphertext) {
        // ciphertext is of the form: (MAC || actual_ciphertext)
        ++ciphertext[aead_encrypt_filter::MACSIZE]; // falsify ciphertext
    }

    // 3. falsify mac if asked

    if (falsify_mac) {
        // ciphertext is of the form: (MAC || actual_ciphertext)
        ++ciphertext[0]; // falsify MAC
    }

    // 4. falsify header if asked
    // see above, alreay submitted to decrypt_filter.

    // 5. now try to decrypt ciphertext into decrypted

    chars decrypted(ciphertext.size() - aead_decrypt_filter::MACSIZE);

    io::array_source source2{ ciphertext.data(), ciphertext.size() };
    io::filtering_istream is2{};
    // is2.exceptions(std::ios_base::failbit | std::ios_base::failbit);
    std::streamsize n{};

    is2.push(decrypt_filter); // (attempt to) decrypt
    is2.push(source2);        // from source2 / ciphertext.

    // read decrypted result into decrypted variable
    is2.read(decrypted.data(), decrypted.size());

    n = is2.gcount();

    is2.pop();

#ifndef NDEBUG
    std::string decrypted_string{ decrypted.cbegin(), decrypted.cend() };
    std::cerr << "decrypted={" << decrypted_string << "}, size=" << n
              << std::endl;
#endif // ! NDEBUG

    if (is2) {
        // decrypted variable has been hopefully filled with decrypted text
        BOOST_CHECK(is2);
        BOOST_CHECK_EQUAL(n, plainblob.size());
        BOOST_CHECK_EQUAL(decrypted.size(), plainblob.size());

        // decryption succeeded and plainblob == decrypted if and only if
        // we don't falsify the ciphertext nor the MAC,
        // nor the key nor the nonce,
        // nor the header.

#ifndef NDEBUG
        std::cerr << "test_of_correctness_input_filter() decryption succeeded"
                  << std::endl;
#endif // ! NDEBUG

        return !falsify_ciphertext && !falsify_mac && !falsify_key &&
               !falsify_nonce && !falsify_header && (plainblob == decrypted);
    } else {
        // decryption failed. This is expected if and only if we falsified
        // the ciphertext OR we falsified the MAC
        // OR we falsified the key
        // OR we falsified the nonce
        // OR we falsified the header (or any combination of those)

#ifndef NDEBUG
        std::cerr << "test_of_correctness_input_filter() decryption failed"
                  << std::endl;
#endif // ! NDEBUG

        return falsify_header || falsify_ciphertext || falsify_mac ||
               falsify_key || falsify_nonce;
    }

    // NOTREACHED (hopefully)

#ifndef NDEBUG
    std::cerr << "falling off the cliff!" << std::endl;
#endif // ! NDEBUG

    return false;
}

void
length_test_output_filter(const std::string& header,
                          const std::string& plaintext)
{
    chars headerblob{ header.cbegin(), header.cend() };

    // create a filter with a random key / random nonce cryptor.
    // multiple use of std::move semantics behing the curtain.
    aead_encrypt_filter encrypt_filter{ aead(),
                                        aead_encrypt_filter::nonce_type(),
                                        headerblob };

    chars plainblob{ plaintext.cbegin(), plaintext.cend() };
    chars ciphertext(aead_encrypt_filter::MACSIZE + plainblob.size());

    io::array_sink sink{ ciphertext.data(), ciphertext.size() };
    io::filtering_ostream os{};
    os.push(encrypt_filter); // first encrypt
    os.push(sink);           // and store result in sink/ciphertext.

    os.write(plainblob.data(), plainblob.size());
    os.flush();

    os.pop();

    // sink (i.e. ciphertext) has been hopefully filled with (MAC || ciphertext)

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      aead_encrypt_filter::MACSIZE + plaintext.size());
}

void
length_test_input_filter(const std::string& header,
                         const std::string& plaintext)
{
    chars headerblob{ header.cbegin(), header.cend() };
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    aead_encrypt_filter::key_type key;     // Create a random key
    aead_encrypt_filter::nonce_type nonce; // Create a random nonce

    aead_encrypt_filter encrypt_filter{ aead(std::move(key)),
                                        nonce,
                                        headerblob };

    chars ciphertext(aead_encrypt_filter::MACSIZE + plainblob.size());

    io::array_source source{ plainblob.data(), plainblob.size() };
    io::filtering_istream is{};
    is.push(encrypt_filter); // encrypt data...
    is.push(source);         // ... from source plainblob

    // read produced ciphertext and store it here:
    is.read(ciphertext.data(), ciphertext.size());

    is.pop();

    // ciphertext has been hopefully filled with (MAC || ciphertext)

    BOOST_CHECK_EQUAL(ciphertext.size(),
                      aead_encrypt_filter::MACSIZE + plaintext.size());
}

BOOST_FIXTURE_TEST_SUITE(sodium_test_suite, SodiumFixture)

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    length_test_output_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{};
    length_test_output_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_header_output_filter)
{
    std::string header{};
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    length_test_output_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_both_output_filter)
{
    std::string header{};
    std::string plaintext{};
    length_test_output_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    length_test_input_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{};
    length_test_input_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_header_input_filter)
{
    std::string header{};
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    length_test_input_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_size_empty_both_input_filter)
{
    std::string header{};
    std::string plaintext{};
    length_test_input_filter(header, plaintext);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_combined_output_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{};
    auto result = test_of_correctness_combined_output_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_header_output_filter)
{
    std::string header{};
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_combined_output_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_both_output_filter)
{
    std::string header{};
    std::string plaintext{};
    auto result = test_of_correctness_combined_output_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_combined_input_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{};
    auto result = test_of_correctness_combined_input_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_header_input_filter)
{
    std::string header{};
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_combined_input_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_combined_empty_both_input_filter)
{
    std::string header{};
    std::string plaintext{};
    auto result = test_of_correctness_combined_input_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_correctness_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_header_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(
      header, plaintext, true, false, false, false, false);

    // Test must succeed, we falsified the header but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_ciphertext_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(
      header, plaintext, false, true, false, false, false);

    // Test must succeed, we falsified the ciphertext but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_mac_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(
      header, plaintext, false, false, true, false, false);

    // Test must succeed, we falsified the MAC but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_key_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(
      header, plaintext, false, false, false, true, false);

    // Test must succeed, we falsified the key but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_nonce_full_output_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_output_filter(
      header, plaintext, false, false, false, false, true);

    // Test must succeed, we falsified the nonce but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(sodium_test_aead_filters_correctness_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(header, plaintext);

    // Test must succeed
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_header_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(
      header, plaintext, true, false, false, false, false);

    // Test must succeed, we falsified the header but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_ciphertext_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(
      header, plaintext, false, true, false, false, false);

    // Test must succeed, we falsified the ciphertext but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_mac_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(
      header, plaintext, false, false, true, false, false);

    // Test must succeed, we falsified the MAC but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_key_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(
      header, plaintext, false, false, false, true, false);

    // Test must succeed, we falsified the key but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE(
  sodium_test_aead_filters_correctness_falsify_nonce_full_input_filter)
{
    std::string header{ "the header" };
    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
    auto result = test_of_correctness_input_filter(
      header, plaintext, false, false, false, false, true);

    // Test must succeed, we falsified the nonce but caught it!
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END()
