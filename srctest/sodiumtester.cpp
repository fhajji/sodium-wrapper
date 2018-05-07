// sodiumtester.cpp -- Test functions for the test harness SodiumTester
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

#include "sodiumtester.h"

#include "common.h"
#include "helpers.h"
#include "nonce.h"
#include "key.h"
#include "keyvar.h"
#include "cryptor.h"
#include "authenticator.h"
#include "cryptor_aead.h"
#include "streamcryptor.h"
#include "filecryptor.h"

#include <stdexcept>
#include <string>
#include <sstream>
#include <fstream>
#include <utility>

using sodium::key;
using sodium::keyvar;
using sodium::nonce;
using sodium::cryptor;
using sodium::cryptor_aead;
using sodium::authenticator;
using sodium::StreamCryptor;
using sodium::FileCryptor;

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

/**
 * Construct the test harness by calling sodium_init() which initializes
 * the libsodium library.
 **/

SodiumTester::SodiumTester()
{
  // We need to initialize libsodium by calling sodium_init() at least
  // once before calling other functions of this library.
  // Calling sodium_init() multiple times doesn't hurt (it may happen
  // e.g. in custom allocators etc.).
  
  if (sodium_init() == -1)
    throw std::runtime_error {"sodium_init() failed"};
}

/**
 * Encrypt a plaintext string with a randomly generated key and nonce
 * and return the result as a string in hexadecimal representation.
 *
 * - We use sodium::nonce<> wrapper to create a store a random nonce
 * - We store the plaintext/ciphertext in a bytes, in unprotected memory
 * - We use our wrapper sodium::cryptor<> to do the encryption
 * - We use our wrapper sodium::cryptor<> to test-decrypt the result
 *   and verify that the decrypted text is the same as the plaintext.
 * - We use our wrapper sodium::bin2hex() to convert the ciphertext into
 *   hexadecimal string, which we return.
 **/

std::string
SodiumTester::test0(const std::string &plaintext)
{  
  cryptor<> sc;                // cryptor with random key
  cryptor<>::nonce_type nonce; // create random nonce;
  
  // transfer plaintext into a binary blob
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // encrypt the plaintext (binary blob) using key/nonce:
  bytes ciphertext = sc.encrypt(plainblob, nonce);

  // (test-) decrypt the ciphertext using same key/nonce:
  bytes decrypted  = sc.decrypt(ciphertext, nonce);
  
  // test of correctness (sanity check): the ciphertext must be
  // equal to the plaintext.
  // 
  // Note that cryptor<>::decrypt() will also have performed
  // a check and thrown a std::runtime_error, should the decryption
  // fail. It can detect corruption of the ciphertext, because
  // cryptor<>::encrypt() encrypts both the plaintext and a MAC
  // that was generated out of the plaintext and of the key/nonce before.
  //
  // We're just double-checking here.

  if (plainblob != decrypted)
    throw std::runtime_error {"test0() message forged (own test)"};

  // finally, convert the bytes of the ciphertext into a hexadecimal
  // string that can be printed, and return that string.

  std::string encrypted_as_hex = sodium::bin2hex<>(ciphertext);
  return encrypted_as_hex;

  // the key will self-destruct here when it goes out of scope.
}

/**
 * Compute the MAC of a plaintext string using a randomly created
 * key. Then:
 *   - verify the unchanged plaintext with the same key/mac
 *   - verify the changed plaintext with the same key/mac
 *   - verify the unchanged plaintext with a different key/mac
 **/

bool
SodiumTester::test1(const std::string &plaintext)
{
  // THIS IS CURRENTLY WRONG:
  // we can even use std::string, since it has a
  // data() and size() interface!
  // authenticator<std::string> sa1;
  
  authenticator<bytes> sa1;

  bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

  // compute the MAC:
  auto mac { sa1.mac(plainblob) };

  // verify the MAC with unchanged data
  if (! sa1.verify(plainblob, mac))
    throw std::runtime_error {"SodiumTester::test1() identical MAC failed"};

  // 2. change plaintext, and re-verify MAC:
  
  // bytes plaintext2{ plaintext };
  // if (plaintext2.size() != 0 &&
  //     (plaintext2[0] = '!') &&
  //     sa1.verify(plaintext2, mac))
  //   throw std::runtime_error {"SodiumTester::test1() different MAC verify"};

  bytes plainblob2{ plaintext.cbegin(), plaintext.cend() };
  if (plainblob2.size() != 0 &&
	  (plainblob2[0] = static_cast<sodium::byte>('!')) &&
	  sa1.verify(plainblob2, mac))
	throw std::runtime_error{ "SodiumTester::test1() different MAC verify" };

  // 3. reverify plaintext with a different key/authenticator

  // create a new authenticator with a (hopefully) different key.
  // the probability that we randomly pick the same key is negligible.
  
  // authenticator<std::string> sa2; // with new random key.
  // if (sa2.verify(plaintext, mac))
  //   throw std::runtime_error {"SodiumTester::test1() different KEYS verify"};

  authenticator<bytes> sa2; // with new random key.
  if (sa2.verify(plainblob, mac))
    throw std::runtime_error {"SodiumTester::test1() different KEYS verify"};

  return true;
}

/**
 * This function tests the key derivation algorithm of libsodium.
 *
 *   - derive a key from pw1, and encrypt plaintext with it.
 *   - derive a new key from pw2, store it in old key location.
 *   - attempt to decrypt encrypted text with it.
 *   - if decryption succeeded (didn't throw), check again manually
 *     that both plaintext and decrypted text are identical.
 *
 * In all cases the same random nonce is (re-)used for encryption
 * and decryption, of course.
 **/

bool
SodiumTester::test2(const std::string &plaintext,
		    const std::string &pw1,
		    const std::string &pw2)
{
  cryptor<>::key_type   key(false); // uninitialized, r/w for now
  cryptor<>::nonce_type nonce {};   // a random nonce

  // random salt, needed by the key derivation function.
  // NOTE: can't move this into Key::setpass(),
  // because we need the salt AND the password to be able
  // to deterministically recreate a key. If we generated
  // the salt in setpass() randomly, users would have no
  // way to recreate the key -- that would be throw-away
  // use-once keys.
  bytes salt(sodium::KEYSIZE_SALT);
  randombytes_buf(salt.data(), salt.size());

  // transfer plaintext into a binary blob
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  // try the first key
  key.setpass(pw1, salt, cryptor<>::key_type::strength_type::medium);
  
  // now encrypt with that key
  bytes ciphertext = cryptor<>(key).encrypt(plainblob, nonce);

  // try the second key
  key.setpass(pw2, salt, cryptor<>::key_type::strength_type::medium);
  
  // now decrypt with that new key.
  // if the key/password was different, we will throw right here and now
  bytes decrypted = cryptor<>(std::move(key)).decrypt(ciphertext, nonce);

  return (decrypted == plainblob);
}

/**
 * This function tests sodium::nonce<>(s).
 *
 *   - We create a nonce<> 'a' with a random value.
 *   - We check that 'a' is indeed 24 bytes (sodium::NONCESIZE_SECRETBOX) long
 *   - We display a hex representation of 'a'
 *   - We copy 'a' into 'a_copy' using the compiler-generated copy constructor
 *   - We test with operator != in constant time if they are different
 *     and throw if they are. We don't measure times here.
 *   - We increment 'a' 5 times, i.e. in pseudo-code: a = a+5.
 *     That is: we call a.increment() 5 times in a row, and we display
 *     each time the hex value of 'a'.  Notice how the FIRST byte changes,
 *     showing indeed that the nonce bytes are interpreted indeed as an
 *     integer in Little Endian format.
 *   - We test with operator > if 'a_copy' is greater than 'a' and throw
 *     if yes. Indeed, a_copy is the original nonce value, and 'a' has been
 *     incremented 5 times already. So 'a_copy' shouldn't be greater than 'a'
 *     The test is in constant time... but we don't measure that here.
 *   - We create a new nonce 'b', but uninitialized. When a nonce is
 *     uninitialized, its backend is default-initialized, i.e. all those
 *     byte(s) of its std::vector are zeroes.
 *   - We check this by:
 *        + displaying a hex representation of 'b'
 *        + checking in constant time if 'b' is all-zeroes with b.is_zero()
 *          and throw if not.
 *   - We increment 'b' by calling b.increment() 5 times in a row. 'b' is
 *     therefore equivalent to '5'. We display hex representation of 'b'
 *   - We exercise operator += by adding 'b' to 'a_copy': i.e. by calling
 *       a_copy += b;
 *     Unless there was an overflow, we should get 'a_copy' == 'a', since
 *     'a' was also incremented 5 times in a row previously.  We check this
 *     with operator != and throw if not equal.
 *
 * We generate the output of the tests as a std::string incrementally
 * by writing the results in a std::ostringstream, and return the string
 * at the end to be displayed by the caller of this function.
 **/

std::string
SodiumTester::test3()
{
  std::ostringstream os; // to collect output
  os << "starting nonce test... -------" << std::endl;

  nonce<> a {}; // a random nonce
  
  // Check at compile time that we got the default size of the nonce:
  static_assert(a.size() == sodium::NONCESIZE_SECRETBOX,
		"SodiumTester::test3() wrong nonce size");
  // when static_assert() isn't possible in some conditions, dynamic assert:
  // if (a.size() != sodium::NONCESIZE_SECRETBOX)
  //   throw std::runtime_error {"SodiumTester::test3() wrong nonce size"};

  os << "a+0: " << sodium::bin2hex<>(a.as_bytes()) << std::endl;
  
  nonce<> a_copy {a};
  if (a != a_copy)
    throw std::runtime_error {"SodiumTester::test3() a != a_copy"};
  
  for (int i: {1,2,3,4,5}) {
    a.increment();
    os << "a+" << i << ": " << sodium::bin2hex<>(a.as_bytes()) << std::endl;
  }

  if (a_copy > a)
    throw std::runtime_error {"SodiumTester::test3() a+5 > a"};
  
  nonce<> b(false); // uninitialized, zeroed?
  os << "b+0: " << sodium::bin2hex<>(b.as_bytes()) << std::endl;
  if (! b.is_zero())
    throw std::runtime_error {"SodiumTester::test3() not initialized to zero"};

  for (int i: {1,2,3,4,5}) {
    static_cast<void>(i); // "use" unused variable i
    b.increment();
  }
  // b is now 5, display it!
  os << "b+5: " << sodium::bin2hex<>(b.as_bytes()) << std::endl;

  a_copy += b; // increment original a by 5 (should be new a)
  if (a_copy != a)
    throw std::runtime_error {"SodiumTester::test3() a_copy + 5 != a+5"};

  os << "---------------- ending nonce test..." << std::endl;
  return os.str();
}

/**
 * This function tests sodium::cryptor_aead.
 *
 * - We encrypt a plain header and plaintext with a random key and nonce,
 *   resulting in a (MAC || ciphertext), which we display in hex format.
 * - Then we decrypt the result (and auto-check against the generated MAC)
 * - We test the MAC by intentionally corrupting the header and decrypting
 *   again. This should fail.
 * - We test the MAC by intentionally corrupting the ciphertext and decrypting
 *   again. This should fail.
 * - To show that we ought to always use different nonces with the same key,
 *   we first re-encrypt with the same key/nonce (and show that we got the
 *   same (MAC || ciphertext) as before, which is bad), and then we increment
 *   the nonce and re-encrypt, to get a different (MAC || ciphertext).
 * - We manually check that the decrypted text == plaintext; even though
 *   if we decrypted successfully, they should be equaly anyway.
 * - Finally, we encrypt / decrypt an empty plaintext with empty header
 *   to test a valid boundary condition.
 **/

std::string
SodiumTester::test4(const std::string &plaintext,
		    const std::string &header)
{
  cryptor_aead<>::key_type   key;   // random key
  cryptor_aead<>::nonce_type nonce; // random nonce
  cryptor_aead<> sc_aead{ std::move(key) };

  std::ostringstream os; // to collect output
  os << "starting AEAD test... ---------" << std::endl;

  // check at compile time that we got the right size of the nonce
  static_assert(nonce.size() == sodium::NONCESIZE_AEAD,
		"SodiumTester::test4() wrong nonce size");
  
  // transfer plaintext and header into binary blobs
  bytes plainblob  {plaintext.cbegin(), plaintext.cend()};
  bytes headerblob {header.cbegin(), header.cend()};

  // now encrypt
  bytes ciphertext_with_mac = sc_aead.encrypt(headerblob,
					       plainblob,
					       nonce);

  os << "encrypted: "
     << sodium::bin2hex<>(ciphertext_with_mac)
     << std::endl;

  // and then decrypt (would throw if there was an error)
  bytes decryptedblob = sc_aead.decrypt(headerblob,
					 ciphertext_with_mac,
					 nonce);

  os << "decrypted okay." << std::endl;

  // now intentionnally corrupt the header and decrypt again:
  bytes header_corrupted(headerblob);
  if (! header_corrupted.empty()) {
    header_corrupted[0] = '!';
    try {
      bytes out = sc_aead.decrypt(header_corrupted,
				   ciphertext_with_mac,
				   nonce);
      os << "ERROR: didn't catch intentional header corruption!" << std::endl;
    }
    catch (std::exception &e) {
      os << "caught header corruption as expected: " << e.what() << std::endl;
    }
  }
  else
    os << "can't test intentional header corruption: empty header."
       << std::endl;
  
  // now, intentionally corrupt the ciphertext and decrypt again:
  if (ciphertext_with_mac.size() > sodium::cryptor_aead<>::MACSIZE)
    ++ciphertext_with_mac[sodium::cryptor_aead<>::MACSIZE];
  try {
    bytes out = sc_aead.decrypt(header_corrupted,
				 ciphertext_with_mac,
				 nonce);
    os << "ERROR: didn't catch intentional ciphertext corruption!"
       << std::endl;
  }
  catch (std::exception &e) {
    os << "caught ciphertext corruption as expected: "
       << e.what() << std::endl;
  }

  // encrypt more text. must increment nonce, because we are reusing key.
  //   we first encrypt without incrementing nonce (DONT'T DO THAT!)
  //   and then encrypt with incrementing nonce (OKAY)
  ciphertext_with_mac = sc_aead.encrypt(headerblob,
					plainblob,
					nonce);
  os << "encrypted (same nonce): "
     << sodium::bin2hex<>(ciphertext_with_mac)
     << std::endl;

  nonce.increment(); // don't forget that!

  ciphertext_with_mac = sc_aead.encrypt(headerblob,
					plainblob,
					nonce);
  os << "encrypted (different nonce): "
     << sodium::bin2hex<>(ciphertext_with_mac)
     << std::endl;

  try {
    bytes decryptedblob = sc_aead.decrypt(headerblob,
					   ciphertext_with_mac,
					   nonce);
    os << "decrypted okay." << std::endl;
    if (decryptedblob == plainblob)
      os << "decrypted == plaintext" << std::endl;
    else
      throw std::runtime_error {"SodiumTester::test4() decrypted != plaintext with new nonce"};
  }
  catch (std::exception & /* e */) {
	  os << "ERROR: unexpectedly can't decrypt with updated nonce."
         << std::endl;
  }

  // Finally, encrypt an empty message
  std::string empty_plaintext {};
  std::string empty_header {};
  nonce.increment();
  bytes empty_plainblob   {empty_plaintext.cbegin(), empty_plaintext.cend()};
  bytes empty_headerblob  {empty_header.cbegin(), empty_header.cend()};
  bytes empty_ciphertext_with_mac = sc_aead.encrypt(empty_headerblob,
						     empty_plainblob,
						     nonce);
  os << "empty encrypted: "
     << sodium::bin2hex<>(empty_ciphertext_with_mac)
     << std::endl;
  try {
    bytes empty_decrypted = sc_aead.decrypt(empty_headerblob,
					     empty_ciphertext_with_mac,
					     nonce);
    if (empty_decrypted == empty_plainblob)
      os << "empty (decrypted) == empty (plainblob)" << std::endl;
    else
      throw std::runtime_error {"SodiumTester::test4() empty decrypted != empty plaintext"};
  }
  catch (std::exception & /* e */) {
    os << "ERROR: caught failed decryption of encryption of empty plaintext"
       << std::endl;
  }
						     
  os << "------------------- ending AEAD test..." << std::endl;
  return os.str();
}

/**
 * This function tests sodium::StreamCryptor:
 *
 * We will test the stream cryptors streamCryptor::encrypt() and
 * streamCryptor::decrypt() on std::ifstream and std::ofstream,
 * i.e. on regular binary files.
 *
 * The preparations consist in intantiating a sodium::StreamCryptor object.
 *
 * - we first create a random key with the right number of bytes
 * - we also create a random nonce with the right number of bytes
 * - from this, we create a sodium::StreamCryptor strm_crypt;
 *   we also specify a granularity of 1024 bytes to be used for
 *   the chunking.
 * - since we squirreled away a copy of the key in strm_crypt, we disable
 *   access to our local key (not needed anymore here).
 *
 * We now want to chunkwise encrypt a binary file.
 * 
 * - we open a file for reading in binary mode, getting a std::ifstream ifs
 * - we open a file for writing in binary mode, getting a std::ofstream ofs
 *   (same name, with .enc appended).
 * - since ifs is _also_ an std::istream, and ofs is also an std::ostream,
 *   we can directly chunkwise encrypt the input stream ifs into the
 *   output stream ofs
 * - then we close the streams. We're done chunkwise encrypting.
 *
 * We finally want to chunkwise decrypt the encrypted file.
 *
 * - we open the encrypted file for reading in binary mode: ifs2.
 * - we open a file for writing in binary mode: ofs2
 *   (same name, with .dec appended).
 * - since ifs2 and ofs2 are also std::istream resp. std::ostream, we
 *   can directly chunkwise decrypt the input stream into the output
 *   stream.
 * - we reuse the same sodium::StreamCryptor object strm_crypt, which
 *   already contains the good key, the right initial nonce, and
 *   the correct blocksize (the decryption takes care to adjust the
 *   block size with MACSIZE, the added MACs for each chunk, automatically).
 * - if the decryption fails for some reason, we throw an error and exit.
 * - the decrypt() function writes to the output stream, i.e. to ofs2,
 *   direcly to the output file.
 * - then we close the streams. We're done chunkwise decrypting.
 *
 * Exercise: compare original file with decrypted file... (NYI).
 *
 **/

bool
SodiumTester::test5(const std::string &filename)
{
  std::size_t                   MYBLKSIZE = 1024;
  
  cryptor_aead<>::key_type   key;
  cryptor_aead<>::nonce_type nonce;
  StreamCryptor              strm_crypt (key, nonce, MYBLKSIZE);

  key.noaccess();
  
  std::ifstream ifs(filename,          std::ios_base::binary);
  std::ofstream ofs(filename + ".enc", std::ios_base::binary);

  if (!ifs || !ofs)
    throw std::runtime_error {"SodiumTester::test5(): Can't open input or output file"};

  // now do the encryption
  strm_crypt.encrypt(ifs, ofs);

  // we're done encrypting, close the (file) streams.
  ofs.close();
  ifs.close();

  // -------------------- now test in reverse ----------------------------

  std::ifstream ifs2(filename + ".enc", std::ios_base::binary);
  std::ofstream ofs2(filename + ".dec", std::ios_base::binary);

  if (!ifs2 || !ofs2)
    throw std::runtime_error {"SodiumTester::test5() can't open second input or output files"};

  // we reuse str_crypt from above: it has saved inside it
  // key, (initial) nonce and the blocksize, so we're safe.
  
  // now do the decryption
  strm_crypt.decrypt(ifs2, ofs2);
  
  // we're done decrypting, close the (file) streams.
  ofs2.close();
  ifs2.close();
  
  return true;
}

bool
SodiumTester::test6(const std::string &filename)
{
  std::size_t             MYBLKSIZE  = 1024;
  
  cryptor_aead<>::key_type   key;
  keyvar<>                   hashkey    (FileCryptor::HASHKEYSIZE);
  cryptor_aead<>::nonce_type nonce;
  FileCryptor                file_crypt (key, nonce, MYBLKSIZE,
				      hashkey, FileCryptor::HASHSIZE);

  key.noaccess();
  hashkey.noaccess();
  
  std::ifstream ifs(filename,           std::ios_base::binary);
  std::ofstream ofs(filename + ".enc2", std::ios_base::binary);

  if (!ifs || !ofs)
    throw std::runtime_error {"SodiumTester::test6(): Can't open input or output file"};

  // now do the encryption
  file_crypt.encrypt(ifs, ofs);

  // we're done encrypting, close the (file) streams.
  ofs.close();
  ifs.close();

  // -------------------- now test in reverse ----------------------------

  std::ifstream ifs2(filename + ".enc2", std::ios_base::binary);
  std::ofstream ofs2(filename + ".dec2", std::ios_base::binary);

  if (!ifs2 || !ofs2)
    throw std::runtime_error {"SodiumTester::test6() can't open second input or output files"};

  // we reuse file_crypt from above: it has saved inside it
  // key, (initial) nonce and the blocksize, so we're safe.
  
  // now do the decryption
  file_crypt.decrypt(ifs2, ofs2);
  
  // we're done decrypting, close the (file) streams.
  ofs2.close();
  ifs2.close();
  
  return true;
}
