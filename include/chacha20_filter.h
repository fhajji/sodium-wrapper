// chacha20_filter.h -- Boost.Iostreams filter for ChaCha20 stream cipher
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

#ifndef _S_CHACHA20_FILTER_H_
#define _S_CHACHA20_FILTER_H_

#include <boost/iostreams/filter/symmetric.hpp>
#include <boost/iostreams/pipeline.hpp>

#include "key.h"
#include "nonce.h"

#include <cstddef>       // std::ptrdiff_t
#include <stdexcept>     // std::runtime_error
#include <algorithm>     // std::min<>

#include <sodium.h>

#define NDEBUG
// #undef NDEBUG

#ifndef NDEBUG
#include <iostream>
#include <string>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace Sodium {

class chacha20_symmetric_filter
{
  /**
   * chacha20_symmetric_filter is a SymmetricFilter model that applies
   * the ChaCha20 stream cipher.  This model can be turned into a
   * DualUse filter using the chacha20_filter class below (see there
   * how to use it in user code).
   **/

 public:
  static constexpr std::size_t KEYSIZE   = Sodium::KEYSIZE_CHACHA20;
  static constexpr std::size_t NONCESIZE = Sodium::NONCESIZE_CHACHA20;
  static constexpr std::size_t BLOCKSIZE = 64; // ChaCha20 blocksize
  
  typedef unsigned char char_type;
  
  using key_type   = Key<KEYSIZE>;
  using nonce_type = Nonce<NONCESIZE>;

  /**
   * Construct a SymmetricFilter model for the ChaCha20 stream cipher.
   * 
   * Parameters:
   *   key   : the secret key used to encrypt/decrypt.
   *   nonce : a public nonce.
   * 
   * Even though we supply a nonce, chacha20_symmetric_filter uses a
   * running internal counter that automatically gets incremented
   * every BLOCKSIZE bytes. This way, long inputs up to 2^64 blocks of
   * BLOCKSIZE bytes each can be encrypted/decrypted in a single or in
   * multiple steps without having to change the nonce in-between.
   * 
   * It is possible to submit single or multipe partial blocks
   * (i.e. blocks smaller than BLOCKSIZE bytes) to this filter for
   * encryption/decryption; even if the sum of all partial blocks
   * exceeds BLOCKSIZE bytes.
   **/
  
  chacha20_symmetric_filter(const key_type &key, const nonce_type &nonce) :
    key_ {key}, nonce_ {nonce}, initptr_ {nullptr}
  {
  }

  /**
   * Filter the sequence [i1,i2) to [o1,o2) using the
   * ChaCha20 algorithm.  Update i1 and o1 after filtering.
   * 
   * At most min(i2-i1, o2-o1) bytes will be filtered, so as
   * not to overflow the input nor the output sequence.
   *
   * Postcondition: i1==i2 or o1==o2 (i.e. one of the input or output
   * sequence must have been completely used up).  If this
   * postcondition doesn't hold, throw a std::runtime_error.
   **/
  
  bool filter(const char_type *&i1, const char_type *i2,
	      char_type       *&o1, char_type       *o2,
	      bool flush)
  {
    // mlen = number of bytes to filter:
    auto mlen = static_cast<unsigned long long>(std::min<std::ptrdiff_t>(i2-i1, o2-o1));

    // initialize initptr to the very start of the complete input sequence
    if (mlen != 0 && initptr_ == nullptr)
      initptr_ = i1;

    // find out the current BLOCKSIZE bytes input block
    // we're starting in:
    uint64_t ic {0};
    if (initptr_ != nullptr)
      ic = (i1 - initptr_) / BLOCKSIZE; // the block we're in
    
    // filter as many bytes as possible from [i1,i2) to [o1,o2)
    // and update i1, and o1 when done.
      
    if (crypto_stream_chacha20_xor_ic(o1,        /* c, destination */
				      i1,        /* m, source */
				      mlen,
				      nonce_.data(),
				      ic,
				      key_.data()) == -1)
      throw std::runtime_error {"Sodium::chacha20_filter::filter() crypto_stream_chacha20_xor_ic() -1"};

#ifndef NDEBUG
    std::cerr << "chacha20_symmetric_filter::filter("
	      << static_cast<const void *>(i1) << ","
	      << static_cast<const void *>(i2) << ","
	      << static_cast<const void *>(o1) << ","
	      << static_cast<const void *>(o2) << ","
	      << flush << ") called" << '\n'
	      << "  [mlen=" << mlen << "]" << '\n'
	      << "  [[i1,i1+mlen)={"
	      << std::string(reinterpret_cast<const char *>(i1),
			     reinterpret_cast<const char *>(i1+mlen))
	      << "}" << '\n'
	      << "  [[o1,o1+mlen)={"
	      << std::string(reinterpret_cast<const char *>(o1),
			     reinterpret_cast<const char *>(o1+mlen))
	      << "}"
	      << "  [ic]=" << ic << '\n'
	      << std::endl;
#endif // ! NDEBUG
    
    i1 += static_cast<std::ptrdiff_t>(mlen);
    o1 += static_cast<std::ptrdiff_t>(mlen);

    // assert that post condition holds:
    if (i1!=i2 && o1!=o2)
      throw std::runtime_error {"Sodium::chacha20_filter::filter() postcondition failed"};
    
    // call again, if there is more data to filter
    return i1 != i2;
  }

  /**
   * Called when the stream is (about to be) closed.  Reset the internal
   * ChaCha20 counter indirectly to 0 by resetting initptr_.
   **/
  
  void close()
  {
#ifndef NDEBUG
    std::cerr << "chacha20_symmetric_filter::close() called" << std::endl;
#endif // ! NDEBUG

    initptr_ = nullptr; // restart with a whole new input sequence
  }
  
 private:
  key_type        key_;
  nonce_type      nonce_;
  const char_type *initptr_; // address of the start of the whole input string
  
}; // chacha20_symmetric_filter

// Turn chacha20_symmetric_filter into a DualUse filter class:
 
class chacha20_filter : public io::symmetric_filter<chacha20_symmetric_filter>
{
  /**
   * chacha20_filter is a DualUseFilter that performs
   * encryption/decryption on a stream.
   * 
   * Parameters:
   *   key   : the secret key used for encryption/decryption
   *   nonce : the public nonce used for encryption/decryption
   * 
   * See also: chacha20_symmetric_filter documentation above.
   *
   * Use chacha20_filter as a DualUseFilter like this:
   * 
   *   #include <boost/iostreams/device/array.hpp>
   *   #include <boost/iostreams/filtering_stream.hpp>
   *   #include "bytestring.h"
   * 
   *   namespace io = boost::iostreams;
   *   typedef io::basic_array_sink<unsigned char>    bytes_array_sink;
   *   typedef io::basic_array_source<unsigned char>  bytes_array_source;
   * 
   *   typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;
   *   typedef io::filtering_stream<io::input,  unsigned char> bytes_filtering_istream;
   *   data_t plainblob { plaintext.cbegin(), plaintext.cend() };
   * 
   *   chacha20_filter::key_type   key;   // Create a random key
   *   chacha20_filter::nonce_type nonce; // Create a random nonce
   * 
   *   chacha20_filter encrypt_filter {10, key, nonce};
   *   chacha20_filter decrypt_filter {12, key, nonce};
   * 
   *   data_t decrypted(plaintext.size());
   * 
   * <---- If using as an OutputFilter:
   *
   *   bytes_array_sink        sink {decrypted.data(), decrypted.size()};
   *   bytes_filtering_ostream os   {};
   *   os.push(encrypt_filter); // first encrypt
   *   os.push(decrypt_filter); // then decrypt again
   *   os.push(sink);           // and store result in sink/derypted.
   * 
   *   os.write(plainblob.data(), plainblob.size());
   *   os.flush();
   * 
   *   os.pop();
   * 
   *   // Collect decrypted result in sink/decrypted
   *   // i.e. in decrypted variable.
   * 
   * ----> If using as an InputFilter:
   * 
   *   bytes_array_source      source {plainblob.data(), plainblob.size()};
   *   bytes_filtering_istream is   {};
   *   is.push(decrypt_filter); // then decrypt again
   *   is.push(encrypt_filter); // first encrypt
   *   is.push(source);         // data to be encrypted in source/plainblob.
   * 
   *   is.read(decrypted.data(), decrypted.size());
   * 
   *   is.pop();
   * 
   *   if (is) {
   *      // collect decrypted result in variable decrypted
   *   } else {
   *      // something went wrong. don't use decrypted.
   *   }
   **/

 private:
  typedef io::symmetric_filter<chacha20_symmetric_filter> base_type;
  typedef chacha20_symmetric_filter                       symmetric_filter_type;
  
 public:
  typedef typename base_type::char_type char_type;
  typedef typename base_type::category  category;

  using key_type   = symmetric_filter_type::key_type;
  using nonce_type = symmetric_filter_type::nonce_type;

  /**
   * chacha20_filter constructs a DualUseFilter out of the
   * chacha20_symmetric_filter SymmetricFilter model to perform
   * encryption/decryption according to the ChaCha20 algorithm.
   * 
   * Parameters:
   *   buffer_size: proceed encryption/decryption in blocks of so many bytes.
   *   key        : secret key used to encrypt/decrypt data with ChaCha20
   *   nonce      : public nonce used to encrypt/decrypt.
   * 
   * Note that to facilitate computations, buffer_size will always be
   * rounded up to the next chacha20_symmetric_filter::BLOCKSIZE
   * boundary, i.e. when BLOCKSIZE is 64 bytes: 20 -> 64, 64 -> 64,
   * 100 -> 128, and so on.
   **/
  
  chacha20_filter(std::streamsize  buffer_size,
		  const key_type   &key,
		  const nonce_type &nonce) :
    base_type(round_up_to_chacha20_blocksize(buffer_size), key, nonce)
  { }

 private:
    std::streamsize round_up_to_chacha20_blocksize(std::streamsize n) const {
      return
	((n / symmetric_filter_type::BLOCKSIZE)+1) *
	symmetric_filter_type::BLOCKSIZE;
    }
};

/**
 * Turn chacha20_filter into a Pipable filter, so in can appear
 * in a pipeline.
 * 
 * Usage:
 *   <to be documented>
 **/
 
BOOST_IOSTREAMS_PIPABLE(chacha20_filter, 0)
 
/**
 * Use like this:
 * 
 *   chacha20_filter chacha20(2048, key, nonce); // 2048: buffer size
 *   ...
 **/

} // namespace Sodium

#endif // _S_CHACHA20_FILTER_H_
