// test_blake2b_tee_filter.cpp -- Test Sodium::blake2b_tee_filter
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
#define BOOST_TEST_MODULE Sodium::blake2b_tee_filter Test
#include <boost/test/included/unit_test.hpp>

#include "blake2b_tee_filter.h"
#include "common.h"
#include "hash.h"

#include <string>

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/filtering_stream.hpp>

using Sodium::blake2b_tee_filter;
using Sodium::Hash;
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
			const typename blake2b_tee_filter<io::file_sink>::key_type key,
			const std::size_t hashsize,
			const std::string &blake2bfile_name,
			const std::string &outfile_name)
{
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  io::file_sink blake2bfile {blake2bfile_name,
                             std::ios_base::out | std::ios_base::binary };
  io::file_sink outfile     {outfile_name,
                             std::ios_base::out | std::ios_base::binary };

  blake2b_tee_filter<io::file_sink> blake2b_filter(blake2bfile, key, hashsize);
  
  io::filtering_ostream os(blake2b_filter | outfile);

  os.write(plainblob.data(), plainblob.size());

  os.flush();
}

bool
verify_hash(const std::string &plaintext,
	    const typename blake2b_tee_filter<io::file_sink>::key_type key,
	    const std::size_t hashsize,
	    const std::string &blake2bfile_name,
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
  
  // 2. Compute the hash independently with the C-API
  data_t hash_c_api(hashsize);
  crypto_generichash(reinterpret_cast<unsigned char *>(hash_c_api.data()),
		     hash_c_api.size(),
		     reinterpret_cast<const unsigned char *>(read_back.data()),
		     read_back.size(),
		     key.data(), key.size());
  
  // 3. Read back the hash computed by blake2b_tee_filter:
  io::file_source ishash(blake2bfile_name,
			 std::ios_base::in | std::ios_base::binary);
  data_t hash_cpp_api(hashsize);
  ishash.read(hash_cpp_api.data(), hash_cpp_api.size());
  ishash.close();

  // 4. Verify the hash with Sodium::Hash (optional)
  Sodium::data_t plainblob_uc {plainblob.cbegin(), plainblob.cend()};
  Hash hasher;

  if (key.size() != 0) {
    Sodium::data_t hash_sodium_api_uc = hasher.hash(plainblob_uc, key, hashsize);
    data_t hash_sodium_api { hash_sodium_api_uc.cbegin(), hash_sodium_api_uc.cend() };
    
    BOOST_CHECK(hash_sodium_api == hash_cpp_api);
  }
  else {
    // keyless version
    Sodium::data_t hash_sodium_api_uc = hasher.hash(plainblob_uc, hashsize);
    data_t hash_sodium_api { hash_sodium_api_uc.cbegin(), hash_sodium_api_uc.cend() };
    
    BOOST_CHECK(hash_sodium_api == hash_cpp_api);
  }
  
  // 5. Compare C-API and C++-API hashes:
  std::string hash_c_api_as_string   {hash_c_api.cbegin(), hash_c_api.cend()};
  std::string hash_cpp_api_as_string {hash_cpp_api.cbegin(), hash_cpp_api.cend()};
  BOOST_TEST_MESSAGE(hash_c_api_as_string);
  BOOST_TEST_MESSAGE(hash_cpp_api_as_string);
  
  return hash_c_api == hash_cpp_api;
}

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture );

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_pipeline_output_device_non_keyless )
{
  blake2b_tee_filter<io::file_sink>::key_type key(blake2b_tee_filter<io::file_sink>::KEYSIZE); // generate a random key for BLAKE2b

  // XXX: keyless version not tested yet.
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string hashfile_name {"/var/tmp/blake2bhashfile.data"};
  const std::string outfile_name  {"/var/tmp/blake2boutfile.data"};
  
  pipeline_output_device(plaintext,
			 key,
			 blake2b_tee_filter<io::file_sink>::HASHSIZE,
			 hashfile_name,
			 outfile_name);

  auto result = verify_hash(plaintext,
			    key,
			    blake2b_tee_filter<io::file_sink>::HASHSIZE,
			    hashfile_name,
			    outfile_name);

  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_pipeline_output_device_keyless )
{
  blake2b_tee_filter<io::file_sink>::key_type key(0, false); // keyless!

  // XXX: keyless version not tested yet.
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string hashfile_name {"/var/tmp/blake2bhashfile.data"};
  const std::string outfile_name  {"/var/tmp/blake2boutfile.data"};
  
  pipeline_output_device(plaintext,
			 key,
			 blake2b_tee_filter<io::file_sink>::HASHSIZE,
			 hashfile_name,
			 outfile_name);

  auto result = verify_hash(plaintext,
			    key,
			    blake2b_tee_filter<io::file_sink>::HASHSIZE,
			    hashfile_name,
			    outfile_name);

  BOOST_CHECK(result);
}


BOOST_AUTO_TEST_SUITE_END ();
