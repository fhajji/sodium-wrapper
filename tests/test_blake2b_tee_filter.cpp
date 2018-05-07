// test_blake2b_tee_filter.cpp -- Test sodium::blake2b_tee_{filter,device}
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
#define BOOST_TEST_MODULE sodium::blake2b_tee_filter Test
#include <boost/test/included/unit_test.hpp>

#include "blake2b_tee_filter.h"
#include "common.h"

#include <string>
#include <cstdio> // std::remove()

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/null.hpp>
#include <boost/iostreams/filtering_stream.hpp>

namespace io = boost::iostreams;

using sodium::blake2b_tee_filter;
using sodium::blake2b_tee_device;
using chars = sodium::chars;

using hash_array_type = typename blake2b_tee_filter<io::null_sink>::hash_type;
using vector_sink     = io::back_insert_device<hash_array_type>;

// a filter which outputs to io::file_sink and tee-s to io::file_sink
using blake2b_to_file_type = blake2b_tee_filter<io::file_sink>;

// an output filter that outputs to io::file_sink and tee-s to vector_sink
using blake2b_to_vector_type = blake2b_tee_device<io::file_sink, vector_sink>;

// an output device that discards the output, and tee-s to vector_sink
using blake2b_to_vector_null_type = blake2b_tee_device<io::null_sink, vector_sink>;

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
delete_file(const char *fname)
{
	int result = std::remove(fname);

	BOOST_CHECK(result == 0);
}

void
pipeline_output_device (const std::string &plaintext,
			const typename blake2b_to_file_type::key_type &key,
			const std::string &blake2bfile_name,
			const std::string &outfile_name)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  io::file_sink blake2bfile {blake2bfile_name,
                             std::ios_base::out | std::ios_base::binary };
  io::file_sink outfile     {outfile_name,
                             std::ios_base::out | std::ios_base::binary };

  if (key.size() != 0) {
    blake2b_to_file_type blake2b_filter(blake2bfile, key,
					blake2b_to_file_type::HASHSIZE);
  
    io::filtering_ostream os(blake2b_filter | outfile);

    os.write(plainblob.data(), plainblob.size());

    os.flush();
  }
  else {
    // keyless version:
    blake2b_to_file_type blake2b_filter(blake2bfile, /* no key param */
					blake2b_to_file_type::HASHSIZE);
  
    io::filtering_ostream os(blake2b_filter | outfile);

    os.write(plainblob.data(), plainblob.size());

    os.flush();
  }
}

bool
verify_hash(const std::string &plaintext,
	    const typename blake2b_to_file_type::key_type &key,
	    const std::string &blake2bfile_name,
	    const std::string &outfile_name)
{
  // 1. Test succeeds only if file outfile_name contains plaintext
  chars plainblob {plaintext.cbegin(), plaintext.cend()};
  
  io::file_source is(outfile_name,
		     std::ios_base::in | std::ios_base::binary);
  chars read_back(plaintext.size());
  is.read(read_back.data(), read_back.size());
  is.close();
  
  BOOST_CHECK(read_back == plainblob);

  std::string read_back_as_string { read_back.cbegin(), read_back.cend() };
  BOOST_TEST_MESSAGE(read_back_as_string);
  
  // 2. Compute the hash independently with the C-API
  hash_array_type hash_c_api(blake2b_tee_filter<io::file_sink>::HASHSIZE);
  crypto_generichash(reinterpret_cast<unsigned char *>(hash_c_api.data()),
		     hash_c_api.size(),
		     reinterpret_cast<unsigned char *>(read_back.data()),
		     read_back.size(),
		     key.size() != 0 ? key.data() : NULL,
		     key.size());
    
  
  // 3. Read back the hash computed by blake2b_* filter/device
  io::file_source ishash(blake2bfile_name,
			 std::ios_base::in | std::ios_base::binary);
  hash_array_type hash_cpp_api(blake2b_to_file_type::HASHSIZE);
  ishash.read(hash_cpp_api.data(), hash_cpp_api.size());
  ishash.close();
  
  // 4. Compare C-API and C++-API hashes:
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash_c_api));
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash_cpp_api));
  
  return hash_c_api == hash_cpp_api;
}

hash_array_type
pipeline_output_device (const std::string &plaintext,
			const typename blake2b_to_vector_type::key_type &key,
			const std::string &outfile_name)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  hash_array_type hash; // will grow
  vector_sink     blake2b_sink(hash);
  
  io::file_sink   outfile {outfile_name,
                           std::ios_base::out | std::ios_base::binary };

  if (key.size() != 0) {
    blake2b_to_vector_type
      blake2b_to_vector_output_device(outfile,      // Device
				      blake2b_sink, // Sink
				      key,
				      blake2b_to_vector_type::HASHSIZE);
    
    io::filtering_ostream os(blake2b_to_vector_output_device);
    
    os.write(plainblob.data(), plainblob.size());
    os.flush();
  }
  else {
    // keyless version
    blake2b_to_vector_type
      blake2b_to_vector_output_device(outfile,      // Device
				      blake2b_sink, // Sink
				      /* no key parameter */
				      blake2b_to_vector_type::HASHSIZE);
    
    io::filtering_ostream os(blake2b_to_vector_output_device);
    
    os.write(plainblob.data(), plainblob.size());
    os.flush();
  }
    
  return hash; // by move semantics
}

bool
verify_hash(const std::string &plaintext,
	    const typename blake2b_to_vector_type::key_type &key,
	    const hash_array_type &hash,
	    const std::string &infile_name)
{
  // 1. Test succeeds only if file infile_name contains plaintext
  chars plainblob {plaintext.cbegin(), plaintext.cend()};
  
  io::file_source is(infile_name,
		     std::ios_base::in | std::ios_base::binary);
  chars read_back(plaintext.size());
  is.read(read_back.data(), read_back.size());
  is.close();
  
  BOOST_CHECK(read_back == plainblob);

  std::string read_back_as_string { read_back.cbegin(), read_back.cend() };
  BOOST_TEST_MESSAGE(read_back_as_string);

  // 2. Compute the hash independently with the C-API
  hash_array_type hash_c_api(blake2b_to_vector_type::HASHSIZE);
  crypto_generichash(reinterpret_cast<unsigned char *>(hash_c_api.data()),
		     hash_c_api.size(),
		     reinterpret_cast<unsigned char *>(read_back.data()),
		     read_back.size(),
		     key.size() != 0 ? key.data() : NULL,
		     key.size());
  
  // 3. Fetch the computed hash from parameter (NO-OP)
  hash_array_type hash_cpp_api {hash};
    
  // 4. Compare C-API and C++-API hashes:
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash_c_api));
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash_cpp_api));
  
  return hash_c_api == hash_cpp_api;
}

hash_array_type
pipeline_output_device (const std::string &plaintext,
			const typename blake2b_to_vector_null_type::key_type &key)
{
  chars plainblob {plaintext.cbegin(), plaintext.cend()};

  hash_array_type hash; // will grow
  vector_sink     blake2b_sink(hash);
  io::null_sink   dev_null_sink;

  if (key.size() != 0) {
    blake2b_to_vector_null_type
      blake2b_to_vector_null_output_device(dev_null_sink, // Device
					   blake2b_sink, // Sink
					   key,
					   blake2b_to_vector_null_type::HASHSIZE);
    
    io::filtering_ostream os(blake2b_to_vector_null_output_device);
    
    os.write(plainblob.data(), plainblob.size());
    os.flush();
  }
  else {
    // keyless vesion
    blake2b_to_vector_null_type
      blake2b_to_vector_null_output_device(dev_null_sink, // Device
					   blake2b_sink, // Sink
					   /* no key parameter */
					   blake2b_to_vector_null_type::HASHSIZE);
    
    io::filtering_ostream os(blake2b_to_vector_null_output_device);
    
    os.write(plainblob.data(), plainblob.size());
    os.flush();
  }
    
  return hash; // by move semantics
}

bool
verify_hash(const std::string &plaintext,
	    const typename blake2b_to_vector_null_type::key_type &key,
	    const hash_array_type &hash)
{
  // 1. Fetch data to check from parameter:
  chars plainblob {plaintext.cbegin(), plaintext.cend()};
  
  BOOST_TEST_MESSAGE(plaintext);

  // 2. Compute the hash independently with the C-API
  hash_array_type hash_c_api(blake2b_to_vector_null_type::HASHSIZE);
  crypto_generichash(reinterpret_cast<unsigned char *>(hash_c_api.data()),
		     hash_c_api.size(),
		     reinterpret_cast<const unsigned char *>(plainblob.data()),
		     plainblob.size(),
		     key.size() != 0 ? key.data() : NULL,
		     key.size());
  
  // 3. Fetch the computed hash from parameter (nothing to do)
      
  // 4. Compare C-API and C++-API hashes:
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash_c_api));
  BOOST_TEST_MESSAGE(sodium::bin2hex<hash_array_type>(hash));
  
  return hash_c_api == hash;
}

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_file )
{
  // generate a random key for BLAKE2b of recommended size:
  blake2b_to_file_type::key_type key(blake2b_to_file_type::KEYSIZE);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string hashfile_name {"blake2bmacfile.data"};
  const std::string outfile_name  {"blake2boutfile.data"};
  
  pipeline_output_device(plaintext,
			 key,
			 hashfile_name,
			 outfile_name);

  auto result = verify_hash(plaintext,
			    key,
			    hashfile_name,
			    outfile_name);

  BOOST_CHECK(result);

  delete_file("blake2bmacfile.data");
  delete_file("blake2boutfile.data");
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_file_keyless )
{
  // generate an empty key for keyless BLAKE2b:
  blake2b_to_file_type::key_type key {0, false};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string hashfile_name {"blake2bmacfile.data"};
  const std::string outfile_name  {"blake2boutfile.data"};
  
  pipeline_output_device(plaintext,
			 key,
			 hashfile_name,
			 outfile_name);

  auto result = verify_hash(plaintext,
			    key,
			    hashfile_name,
			    outfile_name);

  BOOST_CHECK(result);

  delete_file("blake2bmacfile.data");
  delete_file("blake2boutfile.data");
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_vector )
{
  // generate a random key for BLAKE2b of recommended size:
  blake2b_to_vector_type::key_type key(blake2b_to_vector_type::KEYSIZE);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string outfile_name {"blake2boutfile.data"};
  
  hash_array_type hash {pipeline_output_device(plaintext,
					       key,
					       outfile_name)};

  auto result = verify_hash(plaintext,
			    key,
			    hash,
			    outfile_name);

  BOOST_CHECK(result);

  delete_file("blake2boutfile.data");
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_vector_keyless )
{
  // generate an empty key for keyless BLAKE2b
  blake2b_to_vector_type::key_type key {0, false};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  const std::string outfile_name {"blake2boutfile.data"};
  
  hash_array_type hash {pipeline_output_device(plaintext,
					       key,
					       outfile_name)};

  auto result = verify_hash(plaintext,
			    key,
			    hash,
			    outfile_name);

  BOOST_CHECK(result);

  delete_file("blake2boutfile.data");
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_vector_null )
{
  // generate a random key for BLAKE2b with recommended size:
  blake2b_to_vector_null_type::key_type key(blake2b_to_vector_null_type::HASHSIZE);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  hash_array_type hash {pipeline_output_device(plaintext,
					       key)};

  auto result = verify_hash(plaintext,
			    key,
			    hash);

  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_CASE( sodium_test_blake2b_filter_blake2b_to_vector_null_keyless )
{
  // generate an empty key for keyless BLAKE2b:
  blake2b_to_vector_null_type::key_type key {0, false};

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  hash_array_type hash {pipeline_output_device(plaintext,
					       key)};

  auto result = verify_hash(plaintext,
			    key,
			    hash);

  BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END ()
