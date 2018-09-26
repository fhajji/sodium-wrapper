// test_poly1305_tee_filter.cpp -- Test sodium::poly1305_tee_{filter,device}
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
#define BOOST_TEST_MODULE sodium::poly1305_tee_filter Test
#include <boost/test/included/unit_test.hpp>

#include "common.h"
#include "helpers.h"
#include "poly1305_tee_filter.h"

#include <cstdio> // std::remove()
#include <string>

#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/iostreams/filtering_stream.hpp>

namespace io = boost::iostreams;

using sodium::poly1305_tee_device;
using sodium::poly1305_tee_filter;
using chars = sodium::chars;

using mac_array_type = typename poly1305_tee_filter<io::null_sink>::mac_type;
using vector_sink = io::back_insert_device<mac_array_type>;

// a filter which outputs to io::file_sink and tee-s to io::file_sink
using poly1305_to_file_type = poly1305_tee_filter<io::file_sink>;

// an output filter that outputs to io::file_sink and tee-s to vector_sink
using poly1305_to_vector_type = poly1305_tee_device<io::file_sink, vector_sink>;

// an output device that discards the output, and tee-s to vector_sink
using poly1305_to_vector_null_type =
  poly1305_tee_device<io::null_sink, vector_sink>;

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

void
delete_file(const char* fname)
{
    int result = std::remove(fname);

    BOOST_CHECK(result == 0);
}

void
pipeline_output_device(const std::string& plaintext,
                       const typename poly1305_to_file_type::key_type key,
                       const std::string& poly1305file_name,
                       const std::string& outfile_name)
{
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    io::file_sink poly1305file{ poly1305file_name,
                                std::ios_base::out | std::ios_base::binary };
    io::file_sink outfile{ outfile_name,
                           std::ios_base::out | std::ios_base::binary };

    poly1305_to_file_type poly1305_filter(poly1305file, key);

    io::filtering_ostream os(poly1305_filter | outfile);

    os.write(plainblob.data(), plainblob.size());

    os.flush();
}

bool
verify_mac(const std::string& plaintext,
           const typename poly1305_to_file_type::key_type key,
           const std::string& poly1305file_name,
           const std::string& outfile_name)
{
    // 1. Test succeeds only if file outfile_name contains plaintext
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    io::file_source is(outfile_name, std::ios_base::in | std::ios_base::binary);
    chars read_back(plaintext.size());
    is.read(read_back.data(), read_back.size());
    is.close();

    BOOST_CHECK(read_back == plainblob);

    std::string read_back_as_string{ read_back.cbegin(), read_back.cend() };
    BOOST_TEST_MESSAGE(read_back_as_string);

    // 2. Compute the MAC independently with the C-API
    mac_array_type mac_c_api(poly1305_tee_filter<io::file_sink>::MACSIZE);
    crypto_onetimeauth(reinterpret_cast<unsigned char*>(mac_c_api.data()),
                       reinterpret_cast<unsigned char*>(read_back.data()),
                       read_back.size(),
                       key.data());

    // 3. Read back the MAC computed by poly1305_* filter/device
    io::file_source ismac(poly1305file_name,
                          std::ios_base::in | std::ios_base::binary);
    mac_array_type mac_cpp_api(poly1305_to_file_type::MACSIZE);
    ismac.read(mac_cpp_api.data(), mac_cpp_api.size());
    ismac.close();

    // 4. Verify the MAC independently with the C-API
    BOOST_CHECK_EQUAL(crypto_onetimeauth_verify(
                        reinterpret_cast<unsigned char*>(mac_cpp_api.data()),
                        reinterpret_cast<unsigned char*>(read_back.data()),
                        read_back.size(),
                        key.data()),
                      0);

    // 5. Compare C-API and C++-API MACs:
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac_c_api));
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac_cpp_api));

    return mac_c_api == mac_cpp_api;
}

mac_array_type
pipeline_output_device(const std::string& plaintext,
                       const typename poly1305_to_vector_type::key_type key,
                       const std::string& outfile_name)
{
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    mac_array_type mac; // will grow
    vector_sink poly1305_sink(mac);

    io::file_sink outfile{ outfile_name,
                           std::ios_base::out | std::ios_base::binary };

    poly1305_to_vector_type poly1305_vector_output_device(outfile, // Device
                                                          poly1305_sink, // Sink
                                                          key);

    // XXX as long as os isn't closed, mac will
    // remain empty. flushing isn't enough.
    {
        io::filtering_ostream os(poly1305_vector_output_device);

        os.write(plainblob.data(), plainblob.size());
        os.flush();
    }

    return mac; // by move semantics
}

bool
verify_mac(const std::string& plaintext,
           const typename poly1305_to_vector_type::key_type key,
           const mac_array_type& mac,
           const std::string& infile_name)
{
    // 1. Test succeeds only if file infile_name contains plaintext
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    io::file_source is(infile_name, std::ios_base::in | std::ios_base::binary);
    chars read_back(plaintext.size());
    is.read(read_back.data(), read_back.size());
    is.close();

    BOOST_CHECK(read_back == plainblob);

    std::string read_back_as_string{ read_back.cbegin(), read_back.cend() };
    BOOST_TEST_MESSAGE(read_back_as_string);

    // 2. Compute the MAC independently with the C-API
    mac_array_type mac_c_api(poly1305_to_vector_type::MACSIZE);
    crypto_onetimeauth(reinterpret_cast<unsigned char*>(mac_c_api.data()),
                       reinterpret_cast<unsigned char*>(read_back.data()),
                       read_back.size(),
                       key.data());

    // 3. Fetch the computed MAC from parameter (NO-OP)
    mac_array_type mac_cpp_api{ mac };

    // 4. Verify the MAC independently with the C-API
    BOOST_CHECK_EQUAL(
      crypto_onetimeauth_verify(
        reinterpret_cast<const unsigned char*>(mac_cpp_api.data()),
        reinterpret_cast<unsigned char*>(read_back.data()),
        read_back.size(),
        key.data()),
      0);

    // 5. Compare C-API and C++-API MACs:
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac_c_api));
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac_cpp_api));

    return mac_c_api == mac_cpp_api;
}

mac_array_type
pipeline_output_device(
  const std::string& plaintext,
  const typename poly1305_to_vector_null_type::key_type key)
{
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    mac_array_type mac; // will grow
    vector_sink poly1305_sink(mac);
    io::null_sink dev_null_sink;

    poly1305_to_vector_null_type poly1305_vector_null_output_device(
      dev_null_sink, // Device
      poly1305_sink, // Sink
      key);

    // XXX as long as os isn't closed, mac will
    // remain empty. flushing isn't enough.
    {
        io::filtering_ostream os(poly1305_vector_null_output_device);

        os.write(plainblob.data(), plainblob.size());
        os.flush();
    }

    return mac; // by move semantics
}

bool
verify_mac(const std::string& plaintext,
           const typename poly1305_to_vector_null_type::key_type key,
           const mac_array_type& mac)
{
    // 1. Fetch data to check from parameter:
    chars plainblob{ plaintext.cbegin(), plaintext.cend() };

    BOOST_TEST_MESSAGE(plaintext);

    // 2. Compute the MAC independently with the C-API
    mac_array_type mac_c_api(poly1305_to_vector_null_type::MACSIZE);
    crypto_onetimeauth(reinterpret_cast<unsigned char*>(mac_c_api.data()),
                       reinterpret_cast<const unsigned char*>(plainblob.data()),
                       plainblob.size(),
                       key.data());

    // 3. Fetch the computed MAC from parameter (nothing to do)

    // 4. Verify the MAC independently with the C-API
    BOOST_CHECK_EQUAL(
      crypto_onetimeauth_verify(
        reinterpret_cast<const unsigned char*>(mac.data()),
        reinterpret_cast<const unsigned char*>(plainblob.data()),
        plainblob.size(),
        key.data()),
      0);

    // 5. Compare C-API and C++-API MACs:
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac_c_api));
    BOOST_TEST_MESSAGE(sodium::bin2hex<mac_array_type>(mac));

    return mac_c_api == mac;
}

BOOST_FIXTURE_TEST_SUITE(sodium_test_suite, SodiumFixture)

BOOST_AUTO_TEST_CASE(sodium_test_poly1305_filter_poly1305_to_file)
{
    poly1305_to_file_type::key_type key; // generate a random key for Poly1305

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    const std::string macfile_name{ "poly1305macfile.data" };
    const std::string outfile_name{ "poly1305outfile.data" };

    pipeline_output_device(plaintext, key, macfile_name, outfile_name);

    auto result = verify_mac(plaintext, key, macfile_name, outfile_name);

    BOOST_CHECK(result);

    delete_file("poly1305macfile.data");
}

BOOST_AUTO_TEST_CASE(sodium_test_poly1305_filter_poly1305_to_vector)
{
    poly1305_to_vector_type::key_type key; // generate a random key for Poly1305

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    const std::string outfile_name{ "poly1305outfile.data" };

    mac_array_type mac{ pipeline_output_device(plaintext, key, outfile_name) };

    auto result = verify_mac(plaintext, key, mac, outfile_name);

    BOOST_CHECK(result);

    delete_file("poly1305outfile.data");
}

BOOST_AUTO_TEST_CASE(sodium_test_poly1305_filter_poly1305_to_vector_null)
{
    poly1305_to_vector_null_type::key_type
      key; // generate a random key for Poly1305

    std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

    mac_array_type mac{ pipeline_output_device(plaintext, key) };

    auto result = verify_mac(plaintext, key, mac);

    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END()
