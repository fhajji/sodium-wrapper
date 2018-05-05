// blake2b_tee_filter.h -- Boost.Iostreams tee {filter,device} for BLAKE2b
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

#pragma once

#include "keyvar.h"

#include <boost/assert.hpp>
#include <boost/config.hpp>  // BOOST_DEDUCE_TYPENAME.
#include <boost/iostreams/categories.hpp>
#include <boost/iostreams/detail/adapter/device_adapter.hpp>
#include <boost/iostreams/detail/adapter/filter_adapter.hpp>
#include <boost/iostreams/detail/call_traits.hpp>
#include <boost/iostreams/detail/execute.hpp>
#include <boost/iostreams/detail/functional.hpp>  // call_close_all 
#include <boost/iostreams/operations.hpp>
#include <boost/iostreams/pipeline.hpp>
#include <boost/iostreams/traits.hpp>
#include <boost/static_assert.hpp>
#include <boost/type_traits/is_convertible.hpp>
#include <boost/type_traits/is_same.hpp>

#include <stdexcept>     // std::runtime_error
#include <sodium.h>

#ifndef NDEBUG
#include <iostream>
#include <string>
#endif // ! NDEBUG

using namespace boost::iostreams;

namespace sodium {

/**
 * blake2b_tee_filter<Device>
 * 
 * A pipepable output tee filter that computes a BLAKE2b hash for
 * data being sent to it. This filter sends its data unchanged
 * downstream, and, when the stream is about to close, sends
 * the computed BLAKE2b hash to the tee-ed Device.
 * 
 * As a Device, you can use _any_ OutputDevice that provides a
 * write() function (i.e. _not_ Direct Devices). Examples of Device(s)
 * include io::file_sink, io::back_insert_device<STL-Container>, ...
 * 
 * This output filter can be included in a pipe like this:
 *   io::filtering_ostream os(filter1 | filter2 | blake2b_filter | filter3 | somesink);
 *  
 * Usage (example):
 * 
 * // Let's compute a BLAKE2b hash of a std::string and send it to a file
 * // Send the data that is being checksummed downstream, to another file
 *
 * #include "blake2b_tee_filter.h"
 * #include "common.h"
 *
 * #include <string>
 * 
 * #include <boost/iostreams/device/file.hpp>
 * #include <boost/iostreams/filtering_stream.hpp>
 * 
 * namespace io = boost::iostreams;
 * 
 * using sodium::blake2b_tee_filter;
 * using chars = sodium::chars;
 * 
 * // a filter which outputs to io::file_sink and tee-s to io::file_sink
 * using blake2b_to_file_type  = blake2b_tee_filter<io::file_sink>;
 * 
 * // generate a random key for BLAKE2b of recommended key size:
 * blake2b_to_vector_type::key_type key(blake2b_to_vector_type::KEYSIZE);
 * 
 * std::string plaintext {"the quick brown fox jumps over the lazy dog"};
 * chars       plainblob {plaintext.cbegin(), plaintext.cend()};
 * 
 * io::file_sink blake2bfile {"/var/tmp/blake2b.hash",
 *                             std::ios_base::out | std::ios_base::binary };
 * io::file_sink outfile      {"/var/tmp/blake2b.data",
 *                             std::ios_base::out | std::ios_base::binary };
 * 
 * // create an OuputFilter of tee type for hashing with recommended
 * // hash size. Alternatively use keyless hashing by dropping the 'key'
 * // parameter here:
 * blake2b_to_file_type blake2b_filter(blake2bfile,
 *                                     key,
 *                                     blake2b_to_file_type::HASHSIZE);
 *
 * io::filtering_ostream os(blake2b_filter | outfile);
 * 
 * os.write(plainblob.data(), plainblob.size());
 * os.flush();
 **/

template <typename Device>
class blake2b_tee_filter : public detail::filter_adapter<Device>
{
  /**
   * blake2b_tee_filter is like an boost::iostreams::tee_filter that
   * passes all input unmodified through first Sink, and at the same
   * times computes a BLAKE2b hash which it passes to the second
   * Sink when the input stream is about to be closed.
   **/

 public:

  typedef typename detail::param_type<Device>::type param_type;
  typedef typename char_type_of<Device>::type       char_type;
  struct category
    : dual_use_filter_tag,
    multichar_tag,
    closable_tag,
    flushable_tag,
    localizable_tag,
    optimally_buffered_tag
      { };

  BOOST_STATIC_ASSERT(is_device<Device>::value);
  BOOST_STATIC_ASSERT((
    boost::is_convertible< // Using mode_of causes failures on VC6-7.0.
                          BOOST_DEDUCED_TYPENAME boost::iostreams::category_of<Device>::type,
                          output
                         >::value
  ));

  static constexpr std::size_t KEYSIZE      = sodium::KEYSIZE_HASHKEY;
  static constexpr std::size_t KEYSIZE_MIN  = sodium::KEYSIZE_HASHKEY_MIN;
  static constexpr std::size_t KEYSIZE_MAX  = sodium::KEYSIZE_HASHKEY_MAX;
  static constexpr std::size_t HASHSIZE     = crypto_generichash_BYTES;
  static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
  static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;

  using key_type  = keyvar<>;
  using hash_type = sodium::chars; // of hashsize_ elements
  
  /**
   * Construct a blake2b_tee_filter which passes all data through from
   * input stream to the first sink, and computes at the same time a
   * BLAKE2b hash using the provided key. This hash, with the desired
   * size of hashsize will be sent to the second sink when the input
   * stream is about to be closed.
   * 
   * Preconditions:
   *   KEYSIZE_MIN  <= key.size() <= KEYSIZE_MAX,  KEYSIZE recommended
   *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, HASHSIZE recommended
   * 
   *   key.size() may also be 0, in which case keyless version will
   *   be used.
   *
   * If these precondtions are not fulfilled, a std::runtime_error
   * will be thrown.
   **/
  
  explicit blake2b_tee_filter(param_type dev,
			      const key_type &key,
			      const std::size_t hashsize=HASHSIZE) 
    : detail::filter_adapter<Device>(dev), key_ {key}, hashsize_ {hashsize}
  {
    // Some sanity checks first regarding the key and desired size
    if (key.size() != 0 && key.size() < KEYSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filter() key size too small"};
    if (key.size() != 0 && key.size() > KEYSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filter() key size too big"};

    if (hashsize < HASHSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filter() hash size too small"};
    if (hashsize > HASHSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filter() hash size too big"};

    // initialize the BLAKE2b state machine
    if (key.size() != 0)
      crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
    else
      crypto_generichash_init(&state_, NULL, 0, hashsize_);

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_filter::blake2b_tee_filter() called"
	      << std::endl;
#endif // ! NDEBUG
  }

  /**
   * Construct a blake2b_tee_filter which passes all data through from
   * input stream to the first sink, and computes at the same time a
   * BLAKE2b hash. This hash, with the desired size of hashsize will
   * be sent to the second sink when the input stream is about to be
   * closed.
   * 
   * Precondition:
   *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, HASHSIZE recommended
   * 
   * If this precondtion isn't fulfilled, a std::runtime_error
   * will be thrown.
   *
   * This is the keyless version of the previous constructor.
   **/
    
  explicit blake2b_tee_filter(param_type dev,
			      const std::size_t hashsize=HASHSIZE) 
    : detail::filter_adapter<Device>(dev), key_ {0, false}, hashsize_ {hashsize}
  {
    // Some sanity checks first regarding the desired size
    if (hashsize < HASHSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filter(keyless) hash size too small"};
    if (hashsize > HASHSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_filter::blake2b_tee_filterkeyless) hash size too big"};

    // initialize the BLAKE2b state machine (keyless version)
    crypto_generichash_init(&state_, NULL, 0, hashsize_);

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_filter::blake2b_tee_filter(keyless) called"
	      << std::endl;
#endif // ! NDEBUG
  }
  
  template<typename Source>
  std::streamsize read(Source& src, char_type* s, std::streamsize n)
  {
    /**
     * NOTE: This function is not called for some reason! (XXX)
     * If yes, throw an std::runtime_exception (for now).
     * Need to better understand when read() is invoked!
     **/
    
    throw std::runtime_error {"sodium::blake2b_tee_filter::read() called. FIXME!"};
    
    // Read (up to) n chars from src into buffer s
    // and update the BLAKE2b state machine for this chunk
    // using the crypto_generichash_*() streaming API update function:

    std::streamsize result = boost::iostreams::read(src, s, n);

#ifndef NDEBUG
    std::cerr << "WARNING !!! sodium::blake2b_tee_filter::read() called "
	      << "[n=" << n << "] "
	      << '\n';
    if (result != -1) {
      std::string s_as_string {s, s+result};
      std::cerr << "  [s=" << s_as_string << "]"
		<< std::endl;
    }
#endif // ! NDEBUG

    // if (result != -1) {
    //   crypto_generichash_update(&state_,
    // 				   reinterpret_cast<unsigned char *>(s),
    // 				   result);
    // 
    //   // Don't send anything to the second sink yet, since we're
    //   // not done yet computing the BLAKE2b hash.
    // 
    //   // std::streamsize result2 = iostreams::write(this->component(), s, result);
    //   // (void) result2; // Suppress 'unused variable' warning.
    //   // BOOST_ASSERT(result == result2);
    // }
    
    return result; // nr. of bytes read.
  }

  template<typename Sink>
  std::streamsize write(Sink& snk, const char_type* s, std::streamsize n)
  {
    // Write (up to) n chars from the buffer s into the first sink snk.
    // We pass the data unchanged:
    
    std::streamsize result = boost::iostreams::write(snk, s, n);

#ifndef NDEBUG
    std::string s_as_string {s, s+result};
    std::cerr << "sodium::blake2b_tee_filter::write() called "
	      << "[n=" << n << "] "
	      << "[s=" << s_as_string << "] "
	      << "[result=" << result << "]"
	      << std::endl;
#endif // ! NDEBUG
    
    // Update the BLAKE2b state with the chunk we've got:
    crypto_generichash_update(&state_,
			      reinterpret_cast<const unsigned char *>(s),
			      result);

    // Don't write anything yet to the second sink, because we're not
    // done yet computing the BLAKE2b MAC:
    
    // std::streamsize result2 = iostreams::write(this->component(), s, result);
    // (void) result2; // Suppress 'unused variable' warning.
    //  BOOST_ASSERT(result == result2);

    return result; // nr. of bytes (not really) written.
  }

  template<typename Next>
  void close(Next&, BOOST_IOS::openmode)
  {
    // before closing, send the computed BLAKE2b hash:
	auto out = new char_type[hashsize_];
    crypto_generichash_final(&state_,
			     reinterpret_cast<unsigned char *>(out),
			     hashsize_);

#ifndef NDEBUG
    std::streamsize result =
#else
      (void)
#endif // ! NDEBUG
      boost::iostreams::write(this->component(),
			      out,
			      hashsize_);

#ifndef NDEBUG
    hash_type   out_as_hash_type_var {out, out+hashsize_};
    std::string out_as_hex_string    {tohex(out_as_hash_type_var)};
    std::cerr << "sodium::blake2b_tee_filter::close() called "
	      << "[result="   << result << "], "
	      << "[hashsize=" << hashsize_ << "]" << '\n'
	      << "  [out="    << out_as_hex_string << "]"
	      << std::endl;
#endif // ! NDEBUG
    
    BOOST_ASSERT(static_cast<std::size_t>(result) == hashsize_);
      
    // and now close the streams
    detail::close_all(this->component());

    // reset the BLAKE2b state so we can start afresh with new streams
    if (key_.size() != 0)
      crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
    else
      crypto_generichash_init(&state_, NULL, 0, hashsize_);

	delete[] out;
  }

  template<typename Sink>
  bool flush(Sink& snk)
  {
    bool r1 = boost::iostreams::flush(snk);
    bool r2 = boost::iostreams::flush(this->component()); // actually a NO-OP

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_filter::flush() called "
	      << "[r1=" << r1 << ",r2=" << r2 << "]"
	      << std::endl;
#endif // ! NDEBUG
    
    return r1 && r2;
  }

 private:
  key_type                 key_;
  std::size_t              hashsize_;
  crypto_generichash_state state_;
};

BOOST_IOSTREAMS_PIPABLE(blake2b_tee_filter, 1)

template<typename Sink>
blake2b_tee_filter<Sink> blake2b_tee(Sink& snk,
				     const typename blake2b_tee_filter<Sink>::key_type &key,
				     const std::size_t hashsize) 
{ return blake2b_tee_filter<Sink>(snk, key, hashsize); }

template<typename Sink>
blake2b_tee_filter<Sink> blake2b_tee(const Sink& snk,
				     const typename blake2b_tee_filter<Sink>::key_type &key,
				     const std::size_t hashsize) 
{ return blake2b_tee_filter<Sink>(snk, key, hashsize); }


/**
 * blake2b_tee_device<Device, Sink>
 * 
 * An OutputDevice with tee functionality that computes a BLAKE2b hash
 * for data being sent to it. This device sends its data unchanged
 * downstream to a sink of type Device. Then, when the stream is about
 * to close, it sends the computed BLAKE2b hash to the tee-ed device
 * of type Sink.
 * 
 * As a Device and as a Sink, you can use _any_ OutputDevice that
 * provides a write() function (i.e. _not_ Direct Devices). Examples
 * of Device(s) and Sink(s) include io::file_sink,
 * io::back_insert_device<STL-Container>, io::null_sink.
 * 
 * By setting Device to io::null_sink, you can discard the data
 * being BLAKE2b-hashed, while still collecting the hash
 * through Sink. If you need that checksum in a std::vector<char>,
 * simply use an io::back_insert_device<std::vector<char>> as Sink.
 *
 * This OutputDevice can be included in a pipe as a sink (i.e. in
 * last position) like this:
 *   io::filtering_ostream os(filter1 | filter2 | blake2b_device);
 * or if no filtering is needed beforehand:
 *   io::filtering_ostream os(blake2b_device);
 * 
 * Usage (example):
 * 
 * // Let's compute a BLAKE2b hash of a std::string and send
 * //  1. the data being checksummed downstream to Device
 * //  2. the BLAKE2b hash to Sink
 * // In this example, we send data to an output file (Device=io::file_sink),
 * // and the BLAKE2b hash to a std::vector<char>     (Sink=vector_sink)
 *
 * #include "blake2b_tee_filter.h"
 * #include "common.h"
 *
 * #include <string>
 * 
 * #include <boost/iostreams/device/file.hpp>
 * #include <boost/iostreams/device/back_inserter.hpp>
 * #include <boost/iostreams/device/null.hpp>
 * #include <boost/iostreams/filtering_stream.hpp>
 * 
 * namespace io = boost::iostreams;
 * 
 * using sodium::blake2b_tee_device;
 * using chars = sodium::chars;
 * 
 * using hash_array_type = typename blake2b_tee_filter<io::null_sink>::hash_type;
 * using vector_sink    = io::back_insert_device<hash_array_type>;
 * 
 * // an output filter that outputs to io::file_sink and tee-s to vector_sink
 * using blake2b_to_vector_type = blake2b_tee_device<io::file_sink, vector_sink>;
 * 
 * // generate a random key of recommended size for BLAKE2b:
 * blake2b_to_vector_type::key_type key(blake2b_to_vector_type::KEYSIZE);
 * 
 * std::string plaintext {"the quick brown fox jumps over the lazy dog"};
 * chars       plainblob {plaintext.cbegin(), plaintext.cend()};
 *
 * hash_array_type hash; // will grow
 * vector_sink     blake2b_sink(hash);
 * 
 * io::file_sink outfile {"/var/tmp/blake2b.data",
 *                        std::ios_base::out | std::ios_base::binary };
 * 
 * blake2b_to_vector_type
 *   blake2b_to_vector_output_device(outfile,      // Device
 *                                   blake2b_sink, // Sink
 *                                   key,
 *                                   blake2b_to_vector_type::HASHSIZE);
 *  
 * io::filtering_ostream os(blake2b_to_vector_output_device);
 * 
 * os.write(plainblob.data(), plainblob.size());
 * os.flush();
 * 
 * // ------- ALTERNATIVELY:
 * // 
 * // In this example, we discard the data by sending it to a io::null_sink,
 * // and we send the BLAKE2b MAC to a std::vector<char>, i.e. a vector_sink
 * //
 * // everything as above, except for this:
 * 
 * // an output filter that outputs to io::file_sink and tee-s to vector_sink
 * using blake2b_to_vector_null_type = 
 *   blake2b_tee_device<io::file_sink, vector_sink>;
 * 
 * hash_array_type hash; // will grow
 * vector_sink     blake2b_sink(hash);
 * 
 * io::null_sink dev_null_sink;
 *
 * blake2b_to_vector_null_type
 *   blake2b_to_vector_null_output_device(dev_null_sink, // Device
 *                                        blake2b_sink,  // Sink
 *                                        key,
 *                                        blake2b_to_vector_null_type::HASHSIZE);
 * io::filtering_ostream os(blake2b_to_vector_null_output_device);
 * 
 * os.write(plainblob.data(), plainblob.size());
 * os.flush();
 * 
 * // now collect BLAKE2b hash in 'hash'.
 **/

template<typename Device, typename Sink>
class blake2b_tee_device {
public:
  typedef typename detail::param_type<Device>::type  device_param;
  typedef typename detail::param_type<Sink>::type    sink_param;
  typedef typename detail::value_type<Device>::type  device_value;
  typedef typename detail::value_type<Sink>::type    sink_value;
  typedef typename char_type_of<Device>::type        char_type;
  typedef typename
    boost::mpl::if_<
      boost::is_convertible<
                            BOOST_DEDUCED_TYPENAME 
                            boost::iostreams::category_of<Device>::type, 
                            output
                           >,
      output,
      input
    >::type                                    mode;

  BOOST_STATIC_ASSERT(is_device<Device>::value);
  BOOST_STATIC_ASSERT(is_device<Sink>::value);
  BOOST_STATIC_ASSERT((
    boost::is_same<
                   char_type, 
                   BOOST_DEDUCED_TYPENAME char_type_of<Sink>::type
                  >::value
  ));
  BOOST_STATIC_ASSERT((
    boost::is_convertible<
                          BOOST_DEDUCED_TYPENAME boost::iostreams::category_of<Sink>::type, 
                          output
                         >::value
  ));
  struct category
    : mode,
    device_tag,
    closable_tag,
    flushable_tag,
    localizable_tag,
    optimally_buffered_tag
      { };

  static constexpr std::size_t KEYSIZE      = sodium::KEYSIZE_HASHKEY;
  static constexpr std::size_t KEYSIZE_MIN  = sodium::KEYSIZE_HASHKEY_MIN;
  static constexpr std::size_t KEYSIZE_MAX  = sodium::KEYSIZE_HASHKEY_MAX;
  static constexpr std::size_t HASHSIZE     = crypto_generichash_BYTES;
  static constexpr std::size_t HASHSIZE_MIN = crypto_generichash_BYTES_MIN;
  static constexpr std::size_t HASHSIZE_MAX = crypto_generichash_BYTES_MAX;

  using key_type  = keyvar<>;
  using hash_type = sodium::chars; // of hashsize_ elements

  /**
   * Construct a blake2b_tee_device which passes all data through from
   * input stream to the first sink, and computes at the same time a
   * BLAKE2b hash using the provided key. This hash, with the desired
   * size of hashsize will be sent to the second sink when the input
   * stream is about to be closed.
   * 
   * Preconditions:
   *   KEYSIZE_MIN  <= key.size() <= KEYSIZE_MAX,  KEYSIZE recommended
   *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, HASHSIZE recommended
   * 
   *   key.size() may also be 0, in which case keyless version will
   *   be used.
   *
   * If these precondtions are not fulfilled, a std::runtime_error
   * will be thrown.
   **/
  
  blake2b_tee_device(device_param device, sink_param sink,
		     const key_type &key,
		     const std::size_t hashsize)
    : dev_(device), sink_(sink), key_ {key}, hashsize_ {hashsize}
  {
    // Some sanity checks first regarding the key and desired size
    if (key.size() != 0 && key.size() < KEYSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device() key size too small"};
    if (key.size() != 0 && key.size() > KEYSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device() key size too big"};

    if (hashsize < HASHSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device() hash size too small"};
    if (hashsize > HASHSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device() hash size too big"};

    // initialize the BLAKE2b state machine
    if (key.size() != 0)
      crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
    else
      crypto_generichash_init(&state_, NULL, 0, hashsize_);

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_device::blake2b_tee_device() called"
	      << std::endl;
#endif // ! NDEBUG
  }

  /**
   * Construct a blake2b_tee_device which passes all data through from
   * input stream to the first sink, and computes at the same time a
   * BLAKE2b hash. This hash, with the desired size of hashsize will
   * be sent to the second sink when the input stream is about to be
   * closed.
   * 
   * Precondition:
   *   HASHSIZE_MIN <= hashsize   <= HASHSIZE_MAX, HASHSIZE recommended
   * 
   * If this precondtion isn't fulfilled, a std::runtime_error
   * will be thrown.
   *
   * This is the keyless version of the previous constructor.
   **/
    
  explicit blake2b_tee_device(device_param device, sink_param sink,
			      const std::size_t hashsize=HASHSIZE) 
    : dev_(device), sink_(sink), key_ {0, false}, hashsize_ {hashsize}
  {
    // Some sanity checks first regarding the desired size
    if (hashsize < HASHSIZE_MIN)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device(keyless) hash size too small"};
    if (hashsize > HASHSIZE_MAX)
      throw std::runtime_error {"sodium::blake2b_tee_device::blake2b_tee_device(keyless) hash size too big"};

    // initialize the BLAKE2b state machine (keyless version)
    crypto_generichash_init(&state_, NULL, 0, hashsize_);

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_device::blake2b_tee_device(keyless) called"
	      << std::endl;
#endif // ! NDEBUG
  }

  std::streamsize read(char_type* s, std::streamsize n)
  {
    BOOST_STATIC_ASSERT((
      boost::is_convertible<
                            BOOST_DEDUCED_TYPENAME boost::iostreams::category_of<Device>::type, input
                           >::value
    ));

    /**
     * NOTE: This function is not called for some reason! (XXX)
     * If yes, throw an std::runtime_exception (for now).
     * Need to better understand when read() is invoked!
     **/

    throw std::runtime_error {"sodium::blake2b_tee_device::read() called. FIXME!"};

    // Read (up to) n chars from dev_ into buffer s
    // and update the BLAKE2b state machine for this chunk
    // using the crypto_generichash_*() streaming API update function
    
    std::streamsize result1 = boost::iostreams::read(dev_, s, n);

#ifndef NDEBUG
    std::cerr << "WARNING !!! sodium::blake2b_tee_device::read() called "
	      << "[n=" << n << "] "
	      << '\n';
    if (result1 != -1) {
      std::string s_as_string {s, s+result1};
      std::cerr << "  [s=" << s_as_string << "]"
		<< std::endl;
    }
#endif // ! NDEBUG
    
    // if (result1 != -1) {
    //   crypto_generichash_update(&state_,
    // 				   reinterpret_cast<unsigned char *>(s),
    // 				   result1);
    //
    //   // Don't send anything to the sink_ yet, since we're
    //   // not done yet computing the BLAKE2b hash.
    //   // 
    //   // // std::streamsize result2 = iostreams::write(sink_, s, result1);
    //   // // (void) result1; // Suppress 'unused variable' warning.
    //   // // (void) result2;
    //   // BOOST_ASSERT(result1 == result2);
    // }
    
    return result1; // nr. of bytes read.
  }

  std::streamsize write(const char_type* s, std::streamsize n)
  {
    BOOST_STATIC_ASSERT((
      boost::is_convertible<
                            BOOST_DEDUCED_TYPENAME boost::iostreams::category_of<Device>::type, output
                           >::value
    ));

    // Write (up to) n chars from the buffer s into the first sink dev_.
    // We pass the data unchanged:
    
    std::streamsize result1 = boost::iostreams::write(dev_, s, n);

    BOOST_ASSERT(result1 == n); // sanity check: we didn't lose anything
    
#ifndef NDEBUG
    std::string s_as_string {s, s+result1};
    std::cerr << "sodium::blake2b_tee_device::write() called "
	      << "[n=" << n << "] "
	      << "[s=" << s_as_string << "] "
	      << "[result1=" << result1 << "]"
	      << std::endl;
#endif // ! NDEBUG

    // Update the BLAKE2b state with the chunk we've got:
    crypto_generichash_update(&state_,
			      reinterpret_cast<const unsigned char *>(s),
			      result1);

    // Don't write anything yet to the second sink sink_, because we're not
    // done yet computing the BLAKE2b hash:
    
    // std::streamsize result2 = iostreams::write(sink_, s, n);
    // (void) result1; // Suppress 'unused variable' warning.
    // (void) result2;
    // BOOST_ASSERT(result1 == n && result2 == n);
    
    return n; // or result1: nr. of bytes (not really) written.
  }

  void close()
  {
    // before closing, send the computed BLAKE2b MAC:
    auto out = new char_type[hashsize_]; // XXX: actually, char_type of sink_, not of dev_
    crypto_generichash_final(&state_,
			     reinterpret_cast<unsigned char *>(out),
			     hashsize_);

#ifndef NDEBUG
    std::streamsize result =
#else
    (void)
#endif // ! NDEBUG
      boost::iostreams::write(sink_,
			      out,
			      hashsize_);

#ifndef NDEBUG
    hash_type   out_as_hash_type_var {out, out+hashsize_};
    std::string out_as_string        {tohex(out_as_hash_type_var)};
    std::cerr << "sodium::blake2b_tee_device::close() called "
	      << "[result="   << result << "] "
	      << "[hashsize=" << hashsize_ << "]" << '\n'
	      << "  [out="    << out_as_string << "]"
	      << std::endl;
#endif // ! NDEBUG

    // sanity check: we didn't lose anything
    BOOST_ASSERT(static_cast<std::size_t>(result) == hashsize_);

    // And now, close the streams
    detail::execute_all( detail::call_close_all(dev_),
			 detail::call_close_all(sink_) );

    // reset the BLAKE2b state so we can start afresh with new streams:
    if (key_.size() != 0)
      crypto_generichash_init(&state_, key_.data(), key_.size(), hashsize_);
    else
      crypto_generichash_init(&state_, NULL, 0, hashsize_);

	delete[] out;
  }
  
  bool flush()
  {
    bool r1 = boost::iostreams::flush(dev_);
    bool r2 = boost::iostreams::flush(sink_);

#ifndef NDEBUG
    std::cerr << "sodium::blake2b_tee_device::flush() called "
	      << "[r1=" << r1 << ",r2=" << r2 << "]"
	      << std::endl;
#endif // ! NDEBUG
    
    return r1 && r2;
  }
  
  template<typename Locale>
  void imbue(const Locale& loc)
  {
    boost::iostreams::imbue(dev_, loc);
    boost::iostreams::imbue(sink_, loc);
  }

  std::streamsize optimal_buffer_size() const 
  {
    return (std::max) ( boost::iostreams::optimal_buffer_size(dev_), 
			boost::iostreams::optimal_buffer_size(sink_) );
  }
  
private:
    device_value             dev_;
    sink_value               sink_;
    key_type                 key_;
    std::size_t              hashsize_;
    crypto_generichash_state state_;
};

template<typename Device, typename Sink>
blake2b_tee_device<Device, Sink> blake2b_tee(Device& dev, Sink& sink,
					     const typename blake2b_tee_device<Device, Sink>::key_type &key,
					     const std::size_t hashsize)
{ return blake2b_tee_device<Device, Sink>(dev, sink, key, hashsize); }

template<typename Device, typename Sink>
blake2b_tee_device<Device, Sink> blake2b_tee(const Device& dev, Sink& sink,
					     const typename blake2b_tee_device<Device, Sink>::key_type &key,
					     const std::size_t hashsize) 
{ return blake2b_tee_device<Device, Sink>(dev, sink, key, hashsize); }

template<typename Device, typename Sink>
  blake2b_tee_device<Device, Sink> blake2b_tee(Device& dev, const Sink& sink,
					       const typename blake2b_tee_device<Device, Sink>::key_type &key,
					       const std::size_t hashsize) 
{ return blake2b_tee_device<Device, Sink>(dev, sink, key, hashsize); }

template<typename Device, typename Sink>
  blake2b_tee_device<Device, Sink> blake2b_tee(const Device& dev, const Sink& sink,
					       const typename blake2b_tee_device<Device, Sink>::key_type &key,
					       const std::size_t hashsize) 
{ return blake2b_tee_device<Device, Sink>(dev, sink, key, hashsize); }

} // namespace sodium