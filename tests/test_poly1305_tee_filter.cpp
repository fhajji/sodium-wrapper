// test_poly1305_tee_filter.cpp -- Test Sodium::poly1305_tee_filter
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
#define BOOST_TEST_MODULE Sodium::poly1305_tee_filter Test
#include <boost/test/included/unit_test.hpp>

#include "poly1305_tee_filter.h"
#include "common.h"

#include <string>

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using Sodium::poly1305_tee_filter;
using Sodium::tohex;
using data_t = Sodium::data2_t;

namespace io = boost::iostreams;

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

void
pipeline_output_device (const std::string &plaintext,
			const typename poly1305_tee_filter<io::file_sink>::key_type key,
			const std::string &poly1305file_name,
			const std::string &outfile_name)
{
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  io::file_sink poly1305file {poly1305file_name,
                              std::ios_base::out | std::ios_base::binary };
  io::file_sink outfile      {outfile_name,
                              std::ios_base::out | std::ios_base::binary };

  poly1305_tee_filter<io::file_sink> poly1305_filter(poly1305file, key);
  
  io::filtering_ostream os(poly1305_filter | outfile);

  os.write(plainblob.data(), plainblob.size());

  os.flush();
}

bool
verify_mac(const std::string &plaintext,
	   const typename poly1305_tee_filter<io::file_sink>::key_type key,
	   const std::string &poly1305file_name,
	   const std::string &outfile_name)
{
  // 1. Test succeeds only if file outfile_name contains plaintext
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
  io::file_source is(outfile_name,
		     std::ios_base::in | std::ios_base::binary);
  data_t read_back(plaintext.size());
  is.read(read_back.data(), read_back.size());
  is.close();
  
  BOOST_CHECK(read_back == plainblob);

  std::string read_back_as_string { read_back.cbegin(), read_back.cend() };
  BOOST_TEST_MESSAGE(read_back_as_string);
  
  // 2. Compute the MAC independently with the C-API
  data_t mac_c_api(poly1305_tee_filter<io::file_sink>::MACSIZE);
  crypto_onetimeauth(reinterpret_cast<unsigned char *>(mac_c_api.data()),
		     reinterpret_cast<unsigned char *>(read_back.data()),
		     read_back.size(),
		     key.data());
  
  // 3. Read back the MAC computed by poly1305_tee_filter:
  io::file_source ismac(poly1305file_name,
			std::ios_base::in | std::ios_base::binary);
  data_t mac_cpp_api(poly1305_tee_filter<io::file_sink>::MACSIZE);
  ismac.read(mac_cpp_api.data(), mac_cpp_api.size());
  ismac.close();
  
  // 4. Verify the MAC independently with the C-API
  BOOST_CHECK_EQUAL(crypto_onetimeauth_verify(reinterpret_cast<unsigned char *>(mac_cpp_api.data()),
					      reinterpret_cast<unsigned char *>(read_back.data()),
					      read_back.size(),
					      key.data()), 0);

  // 5. Compare C-API and C++-API MACs:
  BOOST_TEST_MESSAGE(tohex(mac_c_api));
  BOOST_TEST_MESSAGE(tohex(mac_cpp_api));
  
  return mac_c_api == mac_cpp_api;
}

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_poly1305_filter_pipeline_output_device )
{
  poly1305_tee_filter<io::file_sink>::key_type key; // generate a random key for Poly1305

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string macfile_name {"/var/tmp/poly1305macfile.data"};
  const std::string outfile_name {"/var/tmp/poly1305outfile.data"};
  
  pipeline_output_device(plaintext,
			 key,
			 macfile_name,
			 outfile_name);

  auto result = verify_mac(plaintext,
			   key,
			   macfile_name,
			   outfile_name);

  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END ();
