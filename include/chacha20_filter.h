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
 private:
  
 public:
  static constexpr std::size_t KEYSIZE   = Sodium::KEYSIZE_CHACHA20;
  static constexpr std::size_t NONCESIZE = Sodium::NONCESIZE_CHACHA20;
  
  typedef unsigned char char_type;

  
  using key_type   = Key<KEYSIZE>;
  using nonce_type = Nonce<NONCESIZE>;

  static constexpr std::size_t BLOCKSIZE = 64; // ChaCha20 blocksize
  
  chacha20_symmetric_filter(const key_type &key, const nonce_type &nonce) :
    key_ {key}, nonce_ {nonce}, initptr_ {nullptr}
  {
  }

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
      throw std::runtime_error {"Sodium::chacha20_filter::filter() crypto_stream_chacha20_xor() -1"};

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
 private:
  typedef io::symmetric_filter<chacha20_symmetric_filter> base_type;
  typedef chacha20_symmetric_filter                       symmetric_filter_type;
  
 public:
  typedef typename base_type::char_type char_type;
  typedef typename base_type::category  category;

  using key_type   = symmetric_filter_type::key_type;
  using nonce_type = symmetric_filter_type::nonce_type;
  
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

BOOST_IOSTREAMS_PIPABLE(chacha20_filter, 0)
 
/**
 * Use like this:
 * 
 *   chacha20_filter chacha20(2048, key, nonce); // 2048: buffer size
 *   ...
 **/

} // namespace Sodium

#endif // _S_CHACHA20_FILTER_H_
