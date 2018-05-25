// aead_aesgcm.h -- AES-GCM AEAD construction
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
* sodium::aead_aesgcm implements the
* AES-GCM AEAD scheme
* as found in TLS.
*
* This scheme is compatible with other libraries, but it is
* not as secure as sodium::xchacha20_poly1305_ietf. If you
* can avoid it, then by all means, use xchacha20_poly1305_ietf
* instead.
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

class aead_aesgcm
{
public:
	constexpr static char *construction_name = "aesgcm";

	static int encrypt(unsigned char *c,
		unsigned long long *clen,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *nsec,
		const unsigned char *npub,
		const unsigned char *k)
	{
		return crypto_aead_aes256gcm_encrypt(c,
			clen,
			m,
			mlen,
			ad,
			adlen,
			nsec,
			npub,
			k);
	};

	static int decrypt(unsigned char *m,
		unsigned long long *mlen,
		unsigned char *nsec,
		const unsigned char *c,
		unsigned long long clen,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *npub,
		const unsigned char *k)
	{
		return crypto_aead_aes256gcm_decrypt(m,
			mlen,
			nsec,
			c,
			clen,
			ad,
			adlen,
			npub,
			k);
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
		const unsigned char *k)
	{
		return crypto_aead_aes256gcm_encrypt_detached(c,
			mac,
			maclen_p,
			m,
			mlen,
			ad,
			adlen,
			nsec,
			npub,
			k);
	};

	static int decrypt_detached(unsigned char *m,
		unsigned char *nsec,
		const unsigned char *c,
		unsigned long long clen,
		const unsigned char *mac,
		const unsigned char *ad,
		unsigned long long adlen,
		const unsigned char *npub,
		const unsigned char *k)
	{
		return crypto_aead_aes256gcm_decrypt_detached(m,
			nsec,
			c,
			clen,
			mac,
			ad,
			adlen,
			npub,
			k);
	};

	static constexpr std::size_t KEYBYTES = crypto_aead_aes256gcm_KEYBYTES;
	static constexpr std::size_t NPUBBYTES = crypto_aead_aes256gcm_NPUBBYTES;
	static constexpr std::size_t ABYTES = crypto_aead_aes256gcm_ABYTES;
};

} // namespace sodium
