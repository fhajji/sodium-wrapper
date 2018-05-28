// secretstream.h -- Encrypted streams with shared secret key.
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
#include "secretstream_xchacha20_poly1305.h"
#include <sodium.h>
#include <stdexcept>
#include <type_traits>

namespace sodium {

template <typename BT = bytes,
	typename F = sodium::secretstream_xchacha20_poly1305,
	typename T = typename std::enable_if<
	std::is_same<F, sodium::secretstream_xchacha20_poly1305>::value
	, int
	>::type
>
class secretstream
{
public:
	static constexpr std::size_t KEYSIZE = F::KEYBYTES;
	static constexpr std::size_t MACSIZE = F::ABYTES;
	static constexpr std::size_t HEADERSIZE = F::HEADERBYTES;
	static constexpr std::size_t MESSAGESIZE = F::MESSAGEBYTES_MAX;

	using bytes_type = BT;
	using key_type = key<KEYSIZE>;
	using state_type = typename F::state_type;

	enum class tag_type : sodium::byte {
		TAG_MESSAGE = F::TAG_MESSAGE,
		TAG_PUSH = F::TAG_PUSH,
		TAG_REKEY = F::TAG_REKEY,
		TAG_FINAL = F::TAG_FINAL
	};

	// convenience functions
	constexpr static tag_type tag_message(void) { return tag_type::TAG_MESSAGE; }
	constexpr static tag_type tag_push(void) { return tag_type::TAG_PUSH; }
	constexpr static tag_type tag_rekey(void) { return tag_type::TAG_REKEY; }
	constexpr static tag_type tag_final(void) { return tag_type::TAG_FINAL; }

	// A secretstream with a new random key
	secretstream() : key_(std::move(key_type())) {}

	// A secretstream with a user-supplied key (copying version)
	secretstream(const key_type &key) : key_(key) {}

	// A secretstream with a user-supplied key (moving version)
	secretstream(key_type &&key) : key_(std::move(key)) {}

	// A copying constructor
	secretstream(const secretstream &other) :
		key_(other.key_),
		state_(other.state_)
	{}

	// A moving constructor
	secretstream(secretstream &&other) :
		key_(std::move(other.key_)),
		state_(std::move(other.state_))
	{}

	// XXX copying and moving assignment operators?

	BT init_push(void) {
		BT header(HEADERSIZE);
		if (F::init_push(&state_,
			reinterpret_cast<unsigned char *>(header.data()),
			reinterpret_cast<const unsigned char *>(key_.data())) != 0)
			throw std::runtime_error{ "secretstream::init_push() failed" };
		return header;
	}

	BT push(const BT &plaintext,
		const BT &added_data,
		const tag_type tag = tag_type::TAG_MESSAGE) {
		BT ciphertext_with_mac(plaintext.size() + MACSIZE);
		if (F::push(&state_,
			reinterpret_cast<unsigned char *>(ciphertext_with_mac.data()), nullptr,
			reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size(),
			(added_data.empty() ? nullptr : reinterpret_cast<const unsigned char *>(added_data.data())), added_data.size(),
			static_cast<unsigned char>(tag)) != 0)
			throw std::runtime_error{ "secretstream::push() failed" };
		return ciphertext_with_mac;
	}

	void init_pull(const BT &header) {
		if (F::init_pull(&state_,
			reinterpret_cast<const unsigned char *>(header.data()),
			reinterpret_cast<const unsigned char *>(key_.data())) != 0)
			throw std::runtime_error{ "secretstream::init_pull() failed" };
	}

	BT pull(const BT &ciphertext_with_mac,
		const BT &added_data,
		tag_type &tag) {
		BT plaintext(ciphertext_with_mac.size() - MACSIZE);
		if (F::pull(&state_,
			reinterpret_cast<unsigned char *>(plaintext.data()), nullptr /* mlen_p */,
			reinterpret_cast<unsigned char *>(&tag),
			reinterpret_cast<const unsigned char *>(ciphertext_with_mac.data()), ciphertext_with_mac.size(),
			(added_data.empty() ? nullptr : reinterpret_cast<const unsigned char *>(added_data.data())), added_data.size()
		) == -1)
			throw std::runtime_error{ "secretstream::pull() failed" };
		return plaintext;
	}

	void rekey(void) {
		F::rekey(&state_);
	}

	// XXX TODO
	// 1. map state_type inside bytes_protected (like aes_ctx.h)
	// 2. write unit tests, git commit.
	// 3. implement convenience for_each()
	//     which will push() for encryption/decryption
	//     using TAG_MESSAGE... TAG_MESSAGE... TAG_FINAL.
	// 4. how can we extend 3. to TAG_PUSH?
	// 5. re-implement file cryptor with secretstream.
	// 6. do we still need streamcryptor? if so, use secretstream as backend.

private:
	key_type key_;
	state_type state_; // XXX currently in unprotected memory
};

} // namespace sodium
