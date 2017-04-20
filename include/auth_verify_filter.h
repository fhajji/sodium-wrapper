// auth_verify_filter.h -- Boost.Iostreams MAC verifying filter for Secret Key Authentication (MAC)
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

#ifndef _S_AUTH_VERIFY_FILTER_H_
#define _S_AUTH_VERIFY_FILTER_H_

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include <stdexcept>

#include <sodium.h>
#include "common.h"
#include "key.h"
#include "auth.h"

#define NDEBUG
// #undef NDEBUG

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace Sodium {

class auth_verify_filter : public io::aggregate_filter<unsigned char> {

  /**
   * Use auth_verify_filter as a DualUse filter like this:
   * 
   *     #include <boost/iostreams/device/array.hpp>
   *     #include <boost/iostreams/filtering_stream.hpp>
   *     #include "bytestring.h"
   * 
   *     using Sodium::auth_mac_filter;
   *     using data_t = Sodium::data_t;
   * 
   *     std::string plaintext {"the quick brown fox jumps over the lazy dog"};
   *     data_t      plainblob {plaintext.cbegin(), plaintext.cend()};
   *     data_t      mac = ... // computed earlier
   *     auth_verify_filter::key_type key { ... }; // same as key used earlier
   * 
   * <---- If using as an OutputFilter:
   * 
   *     namespace io = boost::iostreams;
   *     typedef io::basic_array_sink<unsigned char>             bytes_array_sink;
   *     typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;
   * 
   *     auth_verify_filter verify_filter {key, mac};   // create a MAC verifier filter
   *    
   *     data_t result(1); // where to store result
   * 
   *     bytes_array_sink        sink {result.data(), result.size()};
   *     bytes_filtering_ostream os   {};
   *     os.push(verify_filter);
   *     os.push(sink);
   * 
   *     os.write(plainblob.data(), plainblob.size());
   *     os.flush();
   * 
   *     os.pop();
   * 
   *     // sink (i.e. result[0]) contains 0, '0', or '1'
   *     //   * 0   if attempting to verify an empty stream
   *     //   * '0' if mac doesn't match plainblob, authentified with key
   *     //   * '1' if mac is the MAC of plainblob, using key (success) 
   *
   * CAUTION: Verifying the MAC of an empty stream DOESN'T work!
   *          (we get result[0] == 0, not '0' nor '1' in that case)
   *          At least one 'unsigned char' byte must be sent to the filter.
   * 
   * ----> If using as an InputFilter:
   * 
   *     namespace io = boost::iostreams;
   *     typedef io::basic_array_source<unsigned char>          bytes_array_source;
   *     typedef io::filtering_stream<io::input, unsigned char> bytes_filtering_istream;
   * 
   *     auth_verify_filter verify_filter {key, mac};     // create a MAC verifier filter
   * 
   *     bytes_array_source      source {plainblob.data(), plainblob.size()};
   *     bytes_filtering_istream is   {};
   *     is.push(verify_filter);
   *     is.push(source);
   * 
   *     is.read(result.data(), result.size());
   * 
   *     is.pop();
   * 
   *     // result[0] has been filled with
   *     //   0  : if source / plainblob was empty
   *     //   '0': if mac didn't match source / plainblob and key
   *     //   '1': if mac is the MAC of source / plainblob and key (success)
   *
   * CAUTION: Verifying the MAC of an empty stream DOESN'T work!
   *          (we get result[0] == 0, not '0' nor '1' in that case)
   *          At least one 'unsigned char' byte must be sent to the filter.
   **/

  private:
    typedef io::aggregate_filter<unsigned char> base_type;
  
  public:
    typedef typename base_type::char_type   char_type;
    typedef typename base_type::category    category;
    typedef typename base_type::vector_type vector_type; // data_t

    static constexpr std::size_t MACSIZE = Auth::MACSIZE;
    using key_type = Auth::key_type;
  
    auth_verify_filter(const key_type &key, const data_t &mac) :
      key_ {key}, mac_ {mac}, sa_ {}
    {
      if (mac.size() != MACSIZE)
	throw std::runtime_error {"Sodium::auth_verify_filter::auth_verify_filter wrong MAC size"};
    }

    virtual ~auth_verify_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "auth_verify_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG
      
      bool result = sa_.verify(src, mac_, key_); // verify MAC against src
      data_t result_vector(1);
      result_vector[0] = (result ? '1' : '0');

      dest.swap(result_vector); // efficiently store result vector into dest
    }
    
  private:
    key_type key_;
    data_t   mac_;
    Auth     sa_;

}; // auth_verify_filter

} //namespace Sodium

#endif // _S_AUTH_VERIFY_FILTER_H_
