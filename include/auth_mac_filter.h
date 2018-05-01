// auth_mac_filter.h -- Boost.Iostreams MAC generating filter for Secret Key Authentication (MAC)
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

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include "common.h"
#include "key.h"
#include "authenticator.h"

#include <sodium.h>

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace sodium {

class auth_mac_filter : public io::aggregate_filter<char> {

  /**
   * Use auth_mac_filter as a DualUse filter like this:
   * 
   *     #include <boost/iostreams/device/array.hpp>
   *     #include <boost/iostreams/filtering_stream.hpp>
   * 
   *     using sodium::auth_mac_filter;
   *     using chars = sodium::chars;
   * 
   *     std::string plaintext {"the quick brown fox jumps over the lazy dog"};
   *     chars       plainblob {plaintext.cbegin(), plaintext.cend()};
   * 
   * <---- If using as an OutputFilter:
   * 
   *     namespace io = boost::iostreams;
   * 
   *     auth_mac_filter::key_type  key;               // create a random key
   *     authenticator   auth {std::move(key)};        // create an authenticator
   *     auth_mac_filter mac_filter {std::move(auth)}; // create a MAC creator filter
   * 
   *     chars mac(auth_mac_filter::MACSIZE);  // where to store MAC
   * 
   *     io::array_sink        sink {mac.data(), mac.size()};
   *     io::filtering_ostream os   {};
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
   * 
   *     auth_mac_filter::key_type  key;               // create a random key
   *     authenticator   auth {std::move(key)};        // create an authenticator
   *     auth_mac_filter mac_filter {std::move(auth)}; // create a MAC creator filter
   *
   *     chars mac(auth_mac_filter::MACSIZE);  // where to store MAC
   * 
   *     io::array_source      source {plainblob.data(), plainblob.size()};
   *     io::filtering_istream is   {};
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
    typedef io::aggregate_filter<char> base_type;
  
  public:
    typedef typename base_type::char_type   char_type;
    typedef typename base_type::category    category;
    typedef typename base_type::vector_type vector_type; // sodium::chars
  
    static constexpr std::size_t MACSIZE = authenticator::MACSIZE;
    using key_type = authenticator::key_type;
    
    auth_mac_filter(const authenticator &auth) :
      auth_ {auth}
    { }

	auth_mac_filter(authenticator &&auth) :
		auth_{ std::move(auth) }
	{ }

    virtual ~auth_mac_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "auth_mac_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG

      // Compute MAC:
	  vector_type mac{ auth_.mac(src) }; // uses chars overload

      dest.swap(mac);                   // efficiently store it into dest

      // old dest elements will be destroyed when do_filter()
      // goes out of scope.
    }
    
  private:
    authenticator auth_;
}; // auth_mac_filter

} //namespace sodium