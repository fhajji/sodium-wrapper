// helpers.h -- Some universal helpers
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
#include <sodium.h>
#include <string>
#include <functional>
#include <memory>
#include <tuple>

namespace sodium {

template <typename T=char>
using deleted_unique_ptr = std::unique_ptr<T, std::function<void(T*)>>;

/**
* Compare b1 and b2 in constant time.
*
* This function throws a std::runtime_error if both
* containers don't have the same size.
*
* Wrapped libsodium function:
*   sodium_memcmp()
**/

template <typename BT=bytes>
bool compare(const BT &b1, const BT &b2) {
	if (b1.size() != b2.size())
		throw std::runtime_error{ "sodium::compare() different sizes" };

	return sodium_memcmp(b1.data(), b2.data(), b1.size()) == 0;
}

/**
* Check in constant time if the vector n contains only zeroes.
*
* Wrapped libsodium function:
*   sodium_is_zero()
**/

template <typename BT=bytes>
bool is_zero(const BT &n) {
	return sodium_is_zero(reinterpret_cast<const unsigned char *>(n.data()), n.size()) == 1;
}

/**
* Convert the bytes stored in "in" to a hexadecimal string.
* The underlying libsodium function runs in constant time.
*
* Specify as return type either
*   std::string
* or
*   sodium::string_protected.
* All other return types result in compile failures.
*
* Wrapped libsodium function:
*   sodium_bin2hex()
**/

template <typename BT=bytes, typename RETURN_TYPE=std::string>
typename std::enable_if<
	std::is_same<RETURN_TYPE, std::string>::value ||
	std::is_same<RETURN_TYPE, sodium::string_protected>::value
	, RETURN_TYPE>::type
bin2hex(const BT &in)
{
	// each byte turns into 2-char hex + \0 terminator.
	const std::size_t hexbuf_size = in.size() * 2 + 1;

	// In C++17, we could construct a std::string with hexbuf_size chars,
	// and modify it directly through non-const data(). Unfortunately,
	// in C++11 and C++14, std::string's data() is const only, so we need
	// to copy the data over from sodium::chars to std::string for now.

	// If we were sure that in.size() was small, we could
	// also alloca() on the stack, and just before returning
	// we could stackzero(in.size() + some_align_slack)
	// if clearmem is true. But that would not be portable.
	// So we don't and stick to the heap.

	// CAREFUL: even when using sodium::string_protected, this temp
	// buffer is NOT in protected memory. It is not even zeroed
	// after use, so there is a substantial time window where it 
	// could leak to or be modified by outsiders.
	//
	// XXX use a sodium::bytes_protected buffer instead in this case?
	// In normal other cases, using the heap is much faster though.

	std::unique_ptr<char> hexbuf(new char[hexbuf_size]);

	// convert bytes in in into hex using sodium_bin2hex().
	// hexbuf will contain a \0-terminated C-string.
	static_cast<void>(sodium_bin2hex(hexbuf.get(), hexbuf_size,
		reinterpret_cast<const unsigned char *>(in.data()), in.size()));

	// build a std::string<...>, stripping terminating \0 as well.
	RETURN_TYPE outhex(hexbuf.get());

	// return the string
	return outhex;
}

/**
* Convert the bytes stored in "in" to a hexadecimal string.
* The underlying libsodium function runs in constant time.
*
* If clearmem is true, zero temp buffer on the heap in
* constant time.
* 
* Specify as return type either
*   std::string
* or
*   sodium::string_protected.
* All other return types result in compile failures.
*
* Wrapped libsodium function:
*   sodium_bin2hex()
**/

template <typename BT=bytes, typename RETURN_TYPE=std::string>
typename std::enable_if<
	std::is_same<RETURN_TYPE, std::string>::value ||
	std::is_same<RETURN_TYPE, sodium::string_protected>::value
	, RETURN_TYPE>::type
bin2hex(const BT &in, bool clearmem)
{
	// each byte turns into 2-char hex + \0 terminator.
	const std::size_t hexbuf_size = in.size() * 2 + 1;

	// In C++17, we could construct a std::string with hexbuf_size chars,
	// and modify it directly through non-const data(). Unfortunately,
	// in C++11 and C++14, std::string's data() is const only, so we need
	// to copy the data over from sodium::chars to std::string for now.

	// If we were sure that in.size() was small, we could
	// also alloca() on the stack, and just before returning
	// we could stackzero(in.size() + some_align_slack)
	// if clearmem is true. But that would not be portable.
	// So we don't and stick to the heap.

	// CAREFUL: even when using sodium::string_protected, this temp
	// buffer is NOT in protected memory. Even if it is quickly zeroed
	// after use, there is a small time window where it could leak to
	// or be modified by outsiders.
	//
	// XXX use a sodium::bytes_protected buffer instead in this case?
	// In normal other cases, using the heap is much faster though.

	deleted_unique_ptr<char> hexbuf(new char[hexbuf_size],
		[=](char *buf) {
		if (clearmem)
			sodium_memzero(buf, hexbuf_size);
		delete[] buf;
	});

	// convert bytes in in into hex using sodium_bin2hex().
	// hexbuf will contain a \0-terminated C-string.
	static_cast<void>(sodium_bin2hex(hexbuf.get(), hexbuf_size,
		reinterpret_cast<const unsigned char *>(in.data()), in.size()));

	// build a std::string<...>, stripping terminating \0 as well.
	RETURN_TYPE outhex(hexbuf.get());

	// return the string
	return outhex;
}

/**
* Convert the chars stored in "in", interpreted as hexadecimal,
* to binary.
*
* Set ignore to the characters that the parser should skip,
* e.g. to ":\n\t " to interpret "30:31:32 33:34".
*
* The parser will convert until it hits end of in, or a
* non-ignored char.
* 
* Return the result of the conversion, or raise a
* std::runtime_error() if the underlying libsodium function
* returned an error.
*
* Wrapped libsodium function:
*   sodium_hex2bin()
**/

template <typename BT=bytes>
BT
hex2bin(const std::string &hex,
	const std::string &ignore = "")
{
	std::size_t bin_maxlen = hex.size() >> 1; // XXX fixed length, for now

	BT bin(bin_maxlen);
	const char *max_end;

	std::size_t bin_len;

	int rc = sodium_hex2bin(reinterpret_cast<unsigned char *>(bin.data()), bin.size(),
		hex.data(), hex.size(),
		(ignore == "" ? nullptr : ignore.data()),
		&bin_len,
		&max_end);
	if (rc != 0)
		throw std::runtime_error{ "sodium::hex2bin() failed" };

	if (bin_len != bin_maxlen)
		bin.resize(bin_len);

	return bin;

	// XXX how do we return max_end?
}

/**
* Convert the contents in "in", interpreted as bytes, in base64.
* 
* Specify the desired base64 algorithm via the VARIANT template
* parameter. It MUST be one of the sodium_base64_VARIANT_*
* values.
*
* Specify as return type either
*   std::string
* or
*   sodium::string_protected.
* All other return types result in compile failures.
*
* Return the base64 as a string.
*
* Wrapped libsodium function:
*   sodium_bin2base64()
**/

template <int VARIANT=sodium_base64_VARIANT_ORIGINAL, typename BT=bytes, typename RETURN_TYPE=std::string>
typename std::enable_if<
	(VARIANT == sodium_base64_VARIANT_ORIGINAL ||
	 VARIANT == sodium_base64_VARIANT_ORIGINAL_NO_PADDING ||
	 VARIANT == sodium_base64_VARIANT_URLSAFE ||
	 VARIANT == sodium_base64_VARIANT_URLSAFE_NO_PADDING)
	&&
	(std::is_same<RETURN_TYPE, std::string>::value ||
	 std::is_same<RETURN_TYPE, sodium::string_protected>::value)
	, RETURN_TYPE>::type
bin2base64(const BT &in)
{
	// compute size for base64 output buffer, including trailing \0 byte
	const std::size_t base64buf_size = sodium_base64_encoded_len(in.size(), VARIANT);

	// In C++17, we could construct a std::string with base64buf_size chars,
	// and modify it directly through non-const data(). Unfortunately,
	// in C++11 and C++14, std::string's data() is const only, so we need
	// to copy the data over from sodium::chars to std::string for now.

	// If we were sure that in.size() was small, we could
	// also alloca() on the stack, and just before returning
	// we could stackzero(in.size() + some_align_slack)
	// if clearmem is true. But that would not be portable.
	// So we don't and stick to the heap.

	// CAREFUL: even when using sodium::string_protected, this temp
	// buffer is NOT in protected memory. It is not even zeroed
	// after use, so there is a substantial time window where it 
	// could leak to or be modified by outsiders.
	//
	// XXX use a sodium::bytes_protected buffer instead in this case?
	// In normal other cases, using the heap is much faster though.

	std::unique_ptr<char> base64buf(new char[base64buf_size]);

	// convert bytes in in into base64 using sodium_bin2base64().
	// base64buf will contain a \0-terminated C-string.
	static_cast<void>(sodium_bin2base64(base64buf.get(), base64buf_size,
		reinterpret_cast<const unsigned char *>(in.data()), in.size(),
		VARIANT));

	// build a std::string<...>, stripping terminating \0 as well.
	RETURN_TYPE outbase64(base64buf.get());

	// return the string
	return outbase64;
}

/**
* Convert the contents in "in", interpreted as bytes, in base64.
*
* Specify the desired base64 algorithm via the VARIANT template
* parameter. It MUST be one of the sodium_base64_VARIANT_*
* values.
* 
* Specify as return type either
*   std::string
* or
*   sodium::string_protected.
* All other return types result in compile failures.
* 
* If clearmem is true, zero temp buffer on the heap in
* constant time.
*
* Return the base64 as a string.
*
* Wrapped libsodium function:
*   sodium_bin2base64()
**/

template <int VARIANT=sodium_base64_VARIANT_ORIGINAL, typename BT=bytes, typename RETURN_TYPE=std::string>
typename std::enable_if<
	(VARIANT == sodium_base64_VARIANT_ORIGINAL ||
	 VARIANT == sodium_base64_VARIANT_ORIGINAL_NO_PADDING ||
	 VARIANT == sodium_base64_VARIANT_URLSAFE ||
	 VARIANT == sodium_base64_VARIANT_URLSAFE_NO_PADDING)
	&&
	(std::is_same<RETURN_TYPE, std::string>::value ||
	 std::is_same<RETURN_TYPE, sodium::string_protected>::value)
	, RETURN_TYPE>::type
bin2base64(const BT &in, bool clearmem)
{
	// compute size for base64 output buffer, including trailing \0 byte
	const std::size_t base64buf_size = sodium_base64_encoded_len(in.size(), VARIANT);

	// In C++17, we could construct a std::string with base64buf_size chars,
	// and modify it directly through non-const data(). Unfortunately,
	// in C++11 and C++14, std::string's data() is const only, so we need
	// to copy the data over from sodium::chars to std::string for now.

	// If we were sure that in.size() was small, we could
	// also alloca() on the stack, and just before returning
	// we could stackzero(in.size() + some_align_slack)
	// if clearmem is true. But that would not be portable.
	// So we don't and stick to the heap.

	// CAREFUL: even when using sodium::string_protected, this temp
	// buffer is NOT in protected memory. Even if it is quickly zeroed
	// after use, there is a small time window where it could leak to
	// or be modified by outsiders.
	//
	// XXX use a sodium::bytes_protected buffer instead in this case?
	// In normal other cases, using the heap is much faster though.

	deleted_unique_ptr<char> base64buf(new char[base64buf_size],
		[=](char *buf) {
		if (clearmem)
			sodium_memzero(buf, base64buf_size);
		delete[] buf;
	});

	// convert bytes in in into base64 using sodium_bin2base64().
	// base64buf will contain a \0-terminated C-string.
	static_cast<void>(sodium_bin2base64(base64buf.get(), base64buf_size,
		reinterpret_cast<const unsigned char *>(in.data()), in.size(),
		VARIANT));

	// build a std::string<...>, stripping terminating \0 as well.
	RETURN_TYPE outbase64(base64buf.get());

	// return the string
	return outbase64;
}

template <int VARIANT = sodium_base64_VARIANT_ORIGINAL, typename STRING_TYPE = std::string, typename RETURN_TYPE = bytes>
typename std::enable_if<
(VARIANT == sodium_base64_VARIANT_ORIGINAL ||
	VARIANT == sodium_base64_VARIANT_ORIGINAL_NO_PADDING ||
	VARIANT == sodium_base64_VARIANT_URLSAFE ||
	VARIANT == sodium_base64_VARIANT_URLSAFE_NO_PADDING)
	&&
	(std::is_same<STRING_TYPE, std::string>::value ||
	 std::is_same<STRING_TYPE, sodium::string_protected>::value)
	, RETURN_TYPE>::type
base642bin(const STRING_TYPE &b64,
	const std::string &ignore = "")
{
	// since libsodium doesn't provide the reverse of
	// sodium_base64_encoded_len(size_t bin_len, int variant)
	// to estimate bin_maxlen, we set it conservatively to
	// the size of the base64 representation, assuming
	// that base64-encoded data are ALWAYS larger in terms
	// of bytes than the input data (XXX is that so?)
	std::size_t bin_maxlen = b64.size();

	RETURN_TYPE bin(bin_maxlen);
	const char *max_end;

	std::size_t bin_len;

	int rc = sodium_base642bin(reinterpret_cast<unsigned char *>(bin.data()), bin.size(),
		reinterpret_cast<const char *>(b64.data()), b64.size(),
		(ignore == "" ? nullptr : ignore.data()),
		&bin_len,
		&max_end,
		VARIANT);
	if (rc != 0)
		throw std::runtime_error{ "sodium::base642bin() failed" };

	if (bin_len != bin_maxlen)
		bin.resize(bin_len);

	return bin;

	// XXX how do we return max_end?
}

/**
* Clear len bytes above the current stack pointer
* to overwrite sensitive values that may have been
* temporarily located on the stack.
* 
* Note that these values can still be present in registers.
*
* Wrapped libsodium function:
*   sodium_stackzero()
**/

template <typename BT=bytes>
void stackzero(const std::size_t len) {
	sodium_stackzero(len);
}

} // namespace sodium
