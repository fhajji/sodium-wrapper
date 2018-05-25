// aead_aesgcm_precomputed.h -- AES-GCM AEAD construction with pre-computed keys.
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

#include <sodium.h>

/**
* Interchangeable AEAD encrypt/decrypt types.
*
* These types are meant to be used as a template argument
* in sodium::aead (see aead.h).
*
* sodium::aead_aesgcm_precomputed implements the
* AES-GCM AEAD scheme with precomputed state
* as found in TLS.
*
* This scheme is compatible with other libraries, but it is
* not as secure as sodium::xchacha20_poly1305_ietf. If you
* can avoid it, then by all means, use xchacha20_poly1305_ietf
* instead.
*
* Users of this class are supposed to allocate a
* sodium::aead_aesgcm_precomputed::ctx_type on a
* 16 bytes alignment, and initialize it by calling
* sodium::aead_aesgcm_precomputed::init_ctx() prior
* to calling the *_afternm() encrypt and decrypt
* functions.
*
* One way to allocate a 16-bytes aligned ctx in protected
* memory (recommended, to prevent key leaks) is to
* make use of a sodium::aesctx<> object. See aesctx.h
*
* Only available where hardware acceleration is present,
* as can be verified by libsodium's function
*   int crypto_aead_aes256gcm_is_available(void);
*
* Limits:
*   Maximum number of bytes per message: ???
*   Maximum number of bytes before re-keying: ~350 GB
*   Maximum number of messages without re-keying: ~16 KB
*   In all cases... actual figures depend on message size.
*   Nonces: increment instead of generating randomly when
*           key is to be reused. They are very short (96 bits).
*     "To prevent nonce reuse in a client-server protocol,
*      either use different keys for each direction,
*      or make sure that a bit is masked in one direction,
*      and set in the other." -- libsodium documention.
**/

namespace sodium {

class aead_aesgcm_precomputed
{
public:
	using ctx_type = crypto_aead_aes256gcm_state;

	/**
	* Use like this:
	*
	*   aes_ctx ctx;
	*   init_ctx(ctx.data(), aes_key.data());
	* 
	* before using the other functions below with ctx.data()
	* as the last argument.
	**/

	static int init_ctx(ctx_type *ctx,
		unsigned const char *key)
	{
		return crypto_aead_aes256gcm_beforenm(ctx,
			key);
	}

	static int encrypt(unsigned char *c,
		unsigned long long *clen,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *nsec,
		const unsigned char *npub,
		const ctx_type *ctx)
	{
		return crypto_aead_aes256gcm_encrypt_afternm(c,
			clen,
			m,
			mlen,
			ad,
			adlen,
			nsec,
			npub,
			ctx);
	};

	static int decrypt(unsigned char *m,
		unsigned long long *mlen,
		unsigned char *nsec,
		const unsigned char *c,
		unsigned long long clen,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *npub,
		const ctx_type *ctx)
	{
		return crypto_aead_aes256gcm_decrypt_afternm(m,
			mlen,
			nsec,
			c,
			clen,
			ad,
			adlen,
			npub,
			ctx);
	};
	
	static int encrypt_detached(unsigned char *c,
		unsigned char *mac,
		unsigned long long *maclen_p,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *nsec,
		const unsigned char *npub,
		const ctx_type *ctx)
	{
		return crypto_aead_aes256gcm_encrypt_detached_afternm(c,
			mac,
			maclen_p,
			m,
			mlen,
			ad,
			adlen,
			nsec,
			npub,
			ctx);
	};

	static int decrypt_detached(unsigned char *m,
		unsigned char *nsec,
		const unsigned char *c,
		unsigned long long clen,
		const unsigned char *mac,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *npub,
		const ctx_type *ctx)
	{
		return crypto_aead_aes256gcm_decrypt_detached_afternm(m,
			nsec,
			c,
			clen,
			mac,
			ad,
			adlen,
			npub,
			ctx);
	};

	static constexpr std::size_t KEYBYTES = crypto_aead_aes256gcm_KEYBYTES;
	static constexpr std::size_t NPUBBYTES = crypto_aead_aes256gcm_NPUBBYTES;
	static constexpr std::size_t ABYTES = crypto_aead_aes256gcm_ABYTES;
};

} // namespace sodium
