// cryptor_aead_decrypt_filter.h -- Boost.Iostreams symmetric encryption with AEAD and MAC
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
#include "cryptor_aead.h"

#include <boost/iostreams/categories.hpp>       // tags
#include <boost/iostreams/filter/aggregate.hpp> // aggregate_filter

#include <ios>
#include <stdexcept>
#include <sodium.h>

#ifndef NDEBUG
#include <iostream>
#include <string>
#endif // ! NDEBUG

namespace io = boost::iostreams;

namespace sodium {

	class cryptor_aead_decrypt_filter : public io::aggregate_filter<char> {

		/**
		* Use cryptor_aead_decrypt_filter as a DualUse filter like this:
		*
		*   #include <boost/iostreams/device/array.hpp>
		*   #include <boost/iostreams/filtering_stream.hpp>
		*
		*   using sodium::cryptor_aead_decrypt_filter;
		*   using chars = sodium::chars;
		*
		*   std::string header = ...     // computer earlier...
		*   std::string ciphertext = ... // computed earlier...
		*   chars       headerblob {header.cbegin(), header.cend()};
		*   chars       cipherblob {ciphertext.cbegin(), ciphertext.cend()};
		*
		* <---- If using as an OutputFilter:
		*
		*   namespace io = boost::iostreams;
		*
		*   cryptor_aead_decrypt_filter::key_type   key { ... };   // ... with this key
		*   cryptor_aead_decrypt_filter::nonce_type nonce { ... }; // ... and this nonce.
		*   cryptor_aead<chars> crypt{std::move(key)};
		*   cryptor_aead_ decrypt_filter decrypt_filter {std::move(crypt), nonce, headerblob}; // create a decryptor filter
		*   chars decrypted (ciphertext.size() - cryptor_aead_decrypt_filter::MACSIZE);
		*
		*   try {
		*     io::array_sink         sink {decrypted.data(), decrypted.size()};
		*     io::filtering_ostream  os {};
		*     os.push(decrypt_filter);
		*     os.push(sink);
		*
		*     os.write(cipherblob.data(), cipherblob.size());
		*     os.flush();
		*
		*     os.pop();
		*
		*     // the decrypted result is (hopefully) in sink, i.e. in decrypted.
		*   }
		*   catch (std::exception &e) {
		*     // decryption failed. don't use variable decrypted.
		*   }
		*
		* ----> If using as an InputFilter:
		*
		*   namespace io = boost::iostreams;
		*
		*   cryptor_aead_decrypt_filter::key_type   key { ... };   // ... with this key
		*   cryptor_aead_decrypt_filter::nonce_type nonce { ... }; // ... and this nonce.
		*   cryptor_aead<chars> crypt {std::move(key)};
		*   cryptor_aead_decrypt_filter decrypt_filter {std::move(crypt), nonce, headerblob}; // create a decryptor filter
		*   chars decrypted (ciphertext.size() - cryptor_aead_decrypt_filter::MACSIZE);
		*
		*   io::array_source      source {ciphertext.data(), ciphertext.size()};
		*   io::filtering_istream is     {};
		*   std::streamsize n {};
		*
		*   is.push(decrypt_filter); // (attempt do decrypt)
		*   is.push(source);         // form source / ciphertext.
		*
		*   // read decrypted result into decrypted variable
		*   is.read(decrypted.data(), decrypted.size());
		*   n = is.gcount();
		*   is.pop();
		*
		*   if (is) {
		*     // decrypted variable has been hopefully filled with decrypted text
		*   }
		*   else {
		*     // decryption failed. don't use variable decrypted.
		*   }
		**/

	private:
		typedef io::aggregate_filter<char> base_type;

	public:
		typedef typename base_type::char_type   char_type;
		typedef typename base_type::category    category;
		typedef typename base_type::vector_type vector_type; // sodium::chars

		static constexpr std::size_t MACSIZE = cryptor_aead<vector_type>::MACSIZE;

		using key_type = cryptor_aead<vector_type>::key_type;
		using nonce_type = cryptor_aead<vector_type>::nonce_type;

		cryptor_aead_decrypt_filter(const cryptor_aead<vector_type> &cryptor_aead, const nonce_type &nonce, const vector_type &header) :
			cryptor_aead_{ cryptor_aead }, nonce_{ nonce }, header_{ header }
		{}

		cryptor_aead_decrypt_filter(cryptor_aead<vector_type> &&cryptor_aead, const nonce_type &nonce, const vector_type &header) :
			cryptor_aead_{ std::move(cryptor_aead) }, nonce_{ nonce }, header_{ header }
		{}

		virtual ~cryptor_aead_decrypt_filter()
		{ }

	private:
		virtual void do_filter(const vector_type& src, vector_type& dest) {

#ifndef NDEBUG
			std::string src_string{ src.cbegin(), src.cend() };
			std::cerr << "cryptor_aead_decrypt_filter::do_filter("
				<< src_string << ") called" << std::endl;
#endif // ! NDEBUG

			try {
				if (src.size() < MACSIZE)
					throw std::runtime_error{ "sodium::cryptor_aead_decrypt_filter::do_filter() ciphertext too small for mac" };

				// Try to decrypt the (MAC || ciphertext) passed in src.
				vector_type decrypted{ cryptor_aead_.decrypt(header_, src, nonce_) };

				dest.swap(decrypted); // efficiently store result vector into dest
			}
			catch (std::runtime_error &e) {
				std::string error_message{ e.what() };
				error_message.append("\nsodium::cryptor_aead_decrypt_filter::do_filter() can't decrypt");

#ifndef NDEBUG
				std::cerr << "sodium::cryptor_aead_decrypt_filter::do_filter() "
					<< "throwing exception {" << error_message << "}"
					<< std::endl;
#endif // ! NDEBUG

				throw std::ios_base::failure(error_message);
			}

#ifndef NDEBUG
			std::string dest_string{ dest.cbegin(), dest.cend() };
			std::cerr << "cryptor_aead_decrypt_filter::do_filter() returned {"
				<< dest_string << "}" << std::endl;
#endif // ! NDEBUG
		}

	private:
		cryptor_aead<vector_type> cryptor_aead_;
		nonce_type nonce_;
		vector_type header_;
	}; // cryptor_aead_decrypt_filter

} //namespace sodium
