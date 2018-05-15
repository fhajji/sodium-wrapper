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
* Wrapped libsodium function:
*   sodium_bin2hex()
**/

template <typename BT = bytes>
std::string bin2hex(const BT &in)
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

	std::unique_ptr<char> hexbuf(new char[hexbuf_size]);

	// convert bytes in in into hex using sodium_bin2hex().
	// hexbuf will contain a \0-terminated C-string.
	static_cast<void>(sodium_bin2hex(hexbuf.get(), hexbuf_size,
		reinterpret_cast<const unsigned char *>(in.data()), in.size()));

	// build a std::string, stripping terminating \0 as well.
	std::string outhex(hexbuf.get());

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
* Wrapped libsodium function:
*   sodium_bin2hex()
**/

template <typename BT=bytes>
std::string bin2hex(const BT &in, bool clearmem)
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

	// build a std::string, stripping terminating \0 as well.
	std::string outhex(hexbuf.get());

	// return the string
	return outhex;
}

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
