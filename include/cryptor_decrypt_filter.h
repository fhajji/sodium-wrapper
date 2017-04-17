// cryptor_decrypt_filter.h -- Boost.Iostreams symmetric encryption with MAC
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

#ifndef _S_CRYPTOR_DECRYPT_H_
#define _S_CRYPTOR_DECRYPT_H_

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include <stdexcept>

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

class cryptor_decrypt_filter : public io::aggregate_filter<unsigned char> {

  /**
   * Use cryptor_decrypt_filter like this:
   * 
   *   #include <boost/iostreams/device/array.hpp>
   *   #include <boost/iostreams/filtering_stream.hpp>
   * 
   *   using Sodium::cryptor_decrypt_filter;
   *   using data_t = Sodium::data_t;
   * 
   *   namespace io = boost::iostreams;
   *   typedef io::basic_array_sink<unsigned char>             bytes_array_sink;
   *   typedef io::filtering_stream<io::output, unsigned char> bytes_filtering_ostream;
   * 
   *   data_t ciphertext = ...                           // computed earlier...
   *   cryptor_decrypt_filter::key_type   key { ... };   // ... with this key
   *   cryptor_decrypt_filter::nonce_type nonce { ... }; // ... and this nonce.
   *   cryptor_decrypt_filter             decrypt_filter {key, nonce}; // create a decryptor filter
   *   data_t decrypted (ciphertext.size() - cryptor_decrypt_filter::MACSIZE);
   * 
   *   bytes_array_sink         sink2 {decrypted.data(), decrypted.size()};
   *   bytes_filtering_ostream  os2 {};
   *   os2.push(decrypt_filter);
   *   os2.push(sink2);
   * 
   *   data_t      cipherblob {ciphertext.cbegin(), ciphertext.cend()};
   * 
   *   os2.write(cipherblob.data(), cipherblob.size());
   *   os2.flush();
   * 
   *   os2.pop();
   * 
   *   // the decrypted result is (hopefully) in sink2, i.e. in decrypted.
   *   // if decryption failed, os2.write() / os2.pop() would have raised
   *   // a std::runtime_error.
   *
   * CAUTION: Decrypting an empty stream DOESN'T work!
   *          At least one 'unsigned char' byte must be sent to the filter.
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
  
    cryptor_decrypt_filter(const key_type &key,
			   const nonce_type &nonce) :
      key_ {key}, nonce_ {nonce}, sc_ {}
    {
    }

    virtual ~cryptor_decrypt_filter()
    { }
   
 private:
    virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
      std::cerr << "cryptor_decrypt_filter::do_filter() called" << std::endl;
#endif // ! NDEBUG

      // Try to decrypt the (MAC || ciphertext) passed in src.
      // If decryption fails, bubble up Cryptor's std::runtime_error.
      data_t decrypted = sc_.decrypt(src, key_, nonce_);
      
      dest.swap(decrypted); // efficiently store result vector into dest
    }
    
  private:
    key_type   key_;
    nonce_type nonce_;
    Cryptor    sc_;

}; // cryptor_decrypt_filter

} //namespace Sodium

#endif // _S_AUTH_CRYPTOR_DECRYPT_H_
