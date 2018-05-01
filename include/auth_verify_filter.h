// auth_verify_filter.h -- Boost.Iostreams MAC verifying filter for Secret Key Authentication (MAC)
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

#include "common.h"
#include "key.h"
#include "authenticator.h"

#include <stdexcept>
#include <sodium.h>

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter


#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace sodium {

class auth_verify_filter : public io::aggregate_filter<char> {

  /**
   * Use auth_verify_filter as a DualUse filter like this:
   * 
   *     #include <boost/iostreams/device/array.hpp>
   *     #include <boost/iostreams/filtering_stream.hpp>
   * 
   *     using sodium::auth_mac_filter;
   *     using chars = sodium::chars;
   * 
   *     std::string plaintext {"the quick brown fox jumps over the lazy dog"};
   *     chars       plainblob {plaintext.cbegin(), plaintext.cend()};
   *     chars       mac = ... // computed earlier
   *     auth_verify_filter::key_type key { ... }; // same as key used earlier
   * 
   * <---- If using as an OutputFilter:
   * 
   *     namespace io = boost::iostreams;
   * 
   *     authenticator<chars> auth        {std::move(key)};
   *     auth_verify_filter verify_filter {std::move {auth}, mac}; // create a MAC verifier filter
   *    
   *     chars result(1); // where to store result
   * 
   *     io::array_sink        sink {result.data(), result.size()};
   *     io::filtering_ostream os   {};
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
   * 
   *     authenticator<chars> auth { std::move(key) };
   *     auth_verify_filter   verify_filter {std::move(auth), mac}; // create a MAC verifier filter
   * 
   *     io::array_source      source {plainblob.data(), plainblob.size()};
   *     io::filtering_istream is   {};
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
    typedef io::aggregate_filter<char> base_type;
  
  public:
    typedef typename base_type::char_type   char_type;
    typedef typename base_type::category    category;
    typedef typename base_type::vector_type vector_type; // sodium::chars

    static constexpr std::size_t MACSIZE = authenticator<vector_type>::MACSIZE;
    using key_type = authenticator<vector_type>::key_type;
  
    auth_verify_filter(const authenticator<vector_type> &auth, const vector_type &mac) :
      auth_ {auth}, mac_ {mac}
    {
      if (mac.size() != MACSIZE)
	throw std::runtime_error {"sodium::auth_verify_filter::auth_verify_filter() wrong MAC size"};
    }

	auth_verify_filter(authenticator<vector_type> &&auth, const vector_type &mac) :
		auth_{ std::move(auth) }, mac_{ mac }
	{
		if (mac.size() != MACSIZE)
			throw std::runtime_error{ "sodium::auth_verify_filter::auth_verify_filter() wrong MAC size" };
	}

    virtual ~auth_verify_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "auth_verify_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG

      if (mac_.size() != MACSIZE)
	throw std::runtime_error {"sodium::auth_verify_filter::do_filter() mac wrong size"};

      // Verify MAC against src.
	  bool result = auth_.verify(src, mac_); // uses chars overload
      
      vector_type result_vector(1);
      result_vector[0] = (result ? '1' : '0');

      dest.swap(result_vector); // efficiently store result vector into dest
    }
    
  private:
    authenticator<vector_type> auth_;
    vector_type   mac_;
}; // auth_verify_filter

} //namespace sodium