// cryptor_encrypt_filter.h -- Boost.Iostreams symmetric encryption with MAC
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

#ifndef _S_CRYPTOR_ENCRYPT_FILTER_H_
#define _S_CRYPTOR_ENCRYPT_FILTER_H_

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include <sodium.h>
#include "common.h"
#include "key.h"
#include "nonce.h"
#include "cryptor.h"

#define NDEBUG
// #undef NDEBUG

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace Sodium {

class cryptor_encrypt_filter : public io::aggregate_filter<unsigned char> {

  /**
   * Use cryptor_encrypt_filter as a DualUse filter like this:
   * 
   *     #include <boost/iostreams/device/array.hpp>
   *     #include <boost/iostreams/filtering_stream.hpp>
   *     #include "bytestring.h"
   * 
   *     using Sodium::cryptor_encrypt_filter;
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
   *     cryptor_encrypt_filter::key_type      key;      // Create a random key
   *     cryptor_encrypt_filter::nonce_type    nonce;    // create random nonce
   *     cryptor_encrypt_filter encrypt_filter {key, nonce};  // create a cryptor filter
   * 
   *     data_t ciphertext(encryptor_encrypt_filter::MACSIZE + plainblob.size());
   * 
   *     bytes_array_sink        sink {ciphertext.data(), ciphertext.size()};
   *     bytes_filtering_ostream os   {};
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
   *     typedef io::basic_array_source<unsigned char>          bytes_array_source;
   *     typedef io::filtering_stream<io::input, unsigned char> bytes_filtering_istream;
   * 
   *     cryptor_encrypt_filter::key_type      key;      // Create a random key
   *     cryptor_encrypt_filter::nonce_type    nonce;    // create random nonce
   *     cryptor_encrypt_filter encrypt_filter {key, nonce};  // create a cryptor filter
   * 
   *     data_t ciphertext ( cryptor_encrypt_filter::MACSIZE + plaintext.size() );
   *     bytes_array_source        source {plainblob.data(), plainblob.size()};
   *     bytes_filtering_istream   is     {};
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
    typedef io::aggregate_filter<unsigned char> base_type;
  
  public:
    typedef typename base_type::char_type   char_type;
    typedef typename base_type::category    category;
    typedef typename base_type::vector_type vector_type; // data_t

    static constexpr std::size_t MACSIZE   = Cryptor::MACSIZE;
    
    using key_type   = Cryptor::key_type;
    using nonce_type = Cryptor::nonce_type;
    
    cryptor_encrypt_filter(const key_type &key,
			   const nonce_type &nonce) :
      key_ {key}, nonce_ {nonce}, sc_ {}
    { }

    virtual ~cryptor_encrypt_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "cryptor_encrypt_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG

      // compute (MAC || ciphertext)
      data_t ciphertext_with_mac = sc_.encrypt(src, key_, nonce_);
      dest.swap(ciphertext_with_mac);   // efficiently store it into dest
      
      // old dest elements will be destroyed when do_filter()
      // goes out of scope.
    }
    
  private:
    key_type   key_;
    nonce_type nonce_;
    Cryptor    sc_;

}; // cryptor_encrypt_filter

} //namespace Sodium

#endif // _S_CRYPTOR_ENCRYPT_FILTER_H_
