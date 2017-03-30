// streamsignorpk.h -- Public-key signing streaming interface
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

#ifndef _S_STREAMSIGNORPK_H_
#define _S_STREAMSIGNORPK_H_

#include <sodium.h>

#include "common.h"
#include "key.h"
#include "keypairsign.h"

#include <stdexcept>
#include <istream>
#include <ostream>

namespace Sodium {

class StreamSignorPK {
 public:

  static constexpr std::size_t KEYSIZE_PRIVKEY  = Sodium::KEYSIZE_PRIVKEY_SIGN;
  static constexpr std::size_t SIGNATURE_SIZE   = crypto_sign_BYTES;

  /**
   * A StreamSignorPK will sign streams of potentially unlimited length
   * using the crypto_sign_{init,update,final_create}() libsodium API.
   *
   * The stream will be read in a blockwise fashion with blocks
   * of size at most blocksize bytes.
   * 
   * The constructor takes a private _signing_ Key of size
   * KEYSIZE_PRIVKEY bytes.
   **/

  StreamSignorPK(const Key<KEYSIZE_PRIVKEY> &privkey,
		 const std::size_t          blocksize) :
    privkey_ {privkey}, blocksize_ {blocksize} {
      if (blocksize < 1)
	throw std::runtime_error {"Sodium::StreamSignorPK() wrong blocksize"};

      crypto_sign_init(&state_);
  }

  /**
   * A StreamSignorPK will sign streams of potentially unlimited length
   * using the crypto_sign_{init,update,final_create}() libsodium API.
   *
   * The stream will be read in a blockwise fashion with blocks
   * of size at most blocksize bytes.
   * 
   * The constructor takes a KeyPairSign and uses the privkey part of
   * it to sign the messages.
   **/
  StreamSignorPK(const KeyPairSign &keypair,
		 const std::size_t blocksize) :
    privkey_ {keypair.privkey()}, blocksize_ {blocksize} {
      if (blocksize < 1)
	throw std::runtime_error {"Sodium::StreamSignorPK() wrong blocksize"};
      
      crypto_sign_init(&state_);
  }
  
  /**
   * Sign the data provided by the std::istream istr, using the private
   * signing key provided by the constructor. As soon as the stream
   * reaches eof(), the signature is returned, and the state is reset.
   *
   * The stream is read() blockwise, using blocks of size up to
   * blocksize_ bytes.
   *
   * It is possible to call sign() multiple times.
   *
   * sign() will throw a std::runtime_error if the istr fails.
   **/
  
  data_t sign(std::istream &istr);
  
 private:
  Key<KEYSIZE_PRIVKEY> privkey_;
  crypto_sign_state    state_;
  std::size_t          blocksize_;
};

} // namespace Sodium

#endif // _S_STREAMSIGNORPK_H_
