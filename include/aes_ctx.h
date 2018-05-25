// aesctx.h -- AES context for precomputed keys
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
#include <cassert>

namespace sodium {

class aes_ctx
{
public:
	using ctx_type = crypto_aead_aes256gcm_state;
	const std::size_t ctx_size = sizeof(ctx_type);

	aes_ctx() : ctx_(ctx_size) {}

	ctx_type *data()
	{
		// XXX (placement new?)
		// XXX will reinterpret_cast<> relocalize data?
		ctx_type *retval = reinterpret_cast<ctx_type *>(ctx_.data());
		assert(static_cast<void *>(retval) == static_cast<void *>(ctx_.data()));

		return retval;
	}

	std::size_t size() const { return ctx_.size(); }

private:
	alignas(16) bytes_protected ctx_;
};

} // namespace sodium
