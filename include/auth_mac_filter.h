// auth_mac_filter.h -- Boost.Iostreams MAC generating filter for Secret Key Authentication (MAC)
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

#ifndef _S_AUTH_MAC_FILTER_H_
#define _S_AUTH_MAC_FILTER_H_

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

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

class auth_mac_filter : public io::aggregate_filter<unsigned char> {

  /**
   * Use auth_mac_filter as a DualUse filter like this:
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
   * 
   * <---- If using as an OutputFilter:
   * 
   *     namespace io = boost::iostreams;
   *     typedef io::basic_array_sink<unsigned char>             bytes_array_sink;
   *     typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;
   * 
   *     auth_mac_filter::key_type  key;       // Create a random key
   *     auth_mac_filter mac_filter {key};     // create a MAC creator filter
   * 
   *     data_t mac(auth_mac_filter::MACSIZE); // where to store MAC
   * 
   *     bytes_array_sink        sink {mac.data(), mac.size()};
   *     bytes_filtering_ostream os   {};
   *     os.push(mac_filter);
   *     os.push(sink);
   * 
   *     os.write(plainblob.data(), plainblob.size());
   *     os.flush();
   * 
   *     os.pop();
   * 
   *     // sink (i.e. mac) has been filled with MAC.
   *     // extract MAC from data_t mac.
   *
   * CAUTION: Computing the MAC of an empty stream DOESN'T work!
   *          At least one 'unsigned char' byte must be sent to the filter.
   * 
   * ----> If using as an InputFilter:
   * 
   *     namespace io = boost::iostreams;
   *     typedef io::basic_array_source<unsigned char>          bytes_array_source;
   *     typedef io::filtering_stream<io::input, unsigned char> bytes_filtering_istream;
   * 
   *     auth_mac_filter::key_type  key;       // Create a random key
   *     auth_mac_filter mac_filter {key};     // create a MAC creator filter
   * 
   *     data_t mac(auth_mac_filter::MACSIZE); // where to store MAC
   * 
   *     bytes_array_source      source {plainblob.data(), plainblob.size()};
   *     bytes_filtering_istream is   {};
   *     is.push(mac_filter);
   *     is.push(source);
   * 
   *     is.read(mac.data(), mac.size());
   * 
   *     os.pop();
   * 
   *     // source (i.e. mac) has been filled with MAC.
   *     // extract MAC from data_t mac.
   *
   * CAUTION: Computing the MAC of an empty stream DOESN'T work!
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
    
    auth_mac_filter(const key_type &key) :
      key_ {key}, sa_ {}
    { }

    virtual ~auth_mac_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "auth_mac_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG
      
      data_t mac = sa_.auth(src, key_); // compute MAC
      dest.swap(mac);                   // efficiently store it into dest

      // old dest elements will be destroyed when do_filter()
      // goes out of scope.
    }
    
  private:
    key_type key_;
    Auth     sa_;

}; // auth_mac_filter

} //namespace Sodium

#endif // _S_AUTH_MAC_FILTER_H_
