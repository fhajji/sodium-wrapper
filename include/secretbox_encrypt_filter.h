// secretbox_encrypt_filter.h -- Boost.Iostreams symmetric encryption with MAC
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
#include "nonce.h"
#include "secretbox.h"

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include <sodium.h>

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace sodium {

class secretbox_encrypt_filter : public io::aggregate_filter<char> {

  /**
   * Use secretbox_encrypt_filter as a DualUse filter like this:
   * 
   *     #include <boost/iostreams/device/array.hpp>
   *     #include <boost/iostreams/filtering_stream.hpp>
   * 
   *     using sodium::secretbox_encrypt_filter;
   *     using chars = sodium::chars;
   * 
   *     std::string plaintext {"the quick brown fox jumps over the lazy dog"};
   *     chars       plainblob {plaintext.cbegin(), plaintext.cend()};
   *
   * <---- If using as an OutputFilter:
   * 
   *     namespace io = boost::iostreams;
   * 
   *     secretbox_encrypt_filter::key_type      key;      // Create a random key
   *     secretbox_encrypt_filter::nonce_type    nonce;    // create random nonce
   *     secretbox crypt{ std::move(key) };
   *     secretbox_encrypt_filter encrypt_filter {std::move(crypt), nonce};  // create a secretbox filter
   * 
   *     chars ciphertext(ensecretbox_encrypt_filter::MACSIZE + plainblob.size());
   * 
   *     io::array_sink        sink {ciphertext.data(), ciphertext.size()};
   *     io::filtering_ostream os   {};
   *     os.push(encrypt_filter);
   *     os.push(sink);
   * 
   *     os.write(plainblob.data(), plainblob.size());
   *     os.flush();
   * 
   *     os.pop();
   * 
   *     // sink (i.e. ciphertext) has been filled with (MAC || ciphertext)
   *     // extract ciphertext from variable ciphertext.
   *
   * ----> If using as an InputFilter:
   *
   *     namespace io = boost::iostreams;
   * 
   *     secretbox_encrypt_filter::key_type      key;      // Create a random key
   *     secretbox_encrypt_filter::nonce_type    nonce;    // create random nonce
   *     secretbox crypt{ std::move(key) };
   *     secretbox_encrypt_filter encrypt_filter {std::move(crypt), nonce};  // create a secretbox filter
   * 
   *     chars ciphertext ( secretbox_encrypt_filter::MACSIZE + plaintext.size() );
   *     io::array_source        source {plainblob.data(), plainblob.size()};
   *     io::filtering_istream   is     {};
   *     is.push(encrypt_filter); // encrypt data...
   *     is.push(source);         // from source / plainblob.
   * 
   *     // fetch ciphertext by reading into variable ciphertext
   *     is.read(ciphertext.data(), ciphertext.size());
   *   
   *     is.pop();
   *
   *     // source / ciphertext has been filled with (MAC || ciphertext)
   *     // extract ciphertext from variable ciphertext
   **/

  private:
    typedef io::aggregate_filter<char> base_type;
  
  public:
    typedef typename base_type::char_type   char_type;
    typedef typename base_type::category    category;
    typedef typename base_type::vector_type vector_type; // sodium::chars

    static constexpr std::size_t MACSIZE   = secretbox<vector_type>::MACSIZE;
    
    using key_type   = secretbox<vector_type>::key_type;
    using nonce_type = secretbox<vector_type>::nonce_type;

	secretbox_encrypt_filter(const secretbox<vector_type> &secretbox, const nonce_type &nonce) :
		secretbox_{ secretbox }, nonce_{ nonce }
	{}

	secretbox_encrypt_filter(secretbox<vector_type> &&secretbox, const nonce_type &nonce) :
		secretbox_{ std::move(secretbox) }, nonce_{ nonce }
	{}

    virtual ~secretbox_encrypt_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "secretbox_encrypt_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG

      // compute (MAC || ciphertext)
	  vector_type ciphertext_with_mac{ secretbox_.encrypt(src, nonce_) };
			     
      dest.swap(ciphertext_with_mac);   // efficiently store it into dest
      
      // old dest elements will be destroyed when do_filter()
      // goes out of scope.
    }
    
  private:
    secretbox<vector_type> secretbox_;
    nonce_type nonce_;
}; // secretbox_encrypt_filter

} //namespace sodium