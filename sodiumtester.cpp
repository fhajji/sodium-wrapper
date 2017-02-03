// sodiumtester.cpp -- Test functions for the test harness SodiumTester
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumtester.h"

#include "sodiumcrypter.h"
#include "sodiumauth.h"

#include <stdexcept>
#include <string>

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
 * - We use libsodium's randombytes_buf() to generate random key/nonce
 * - We store the key in a key_t, which is located in protected memory
 * - We store the plaintext/cyphertext in a data_t, which is unprotected
 * - We use our wrapper SodiumCrypter to do the encryption
 * - We use our wrapper SodiumCrypter to test-decrypt the result
 *   and verify that the decrypted text is the same as the plaintext.
 * - We use our wrapper SodiumCrypter to convert the cyphertext into
 *   hexadecimal string, which we return.
 **/

std::string
SodiumTester::test0(const std::string &plaintext)
{  
  using data_t = SodiumCrypter::data_t; // unprotected memory
  using key_t  = SodiumCrypter::key_t;  // mprotect()ed memory for keys
  
  SodiumCrypter sc {}; // encryptor, decryptor, hexifior.

  // let's get the sizes in bytes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // create a random key:
  key_t key(key_size); // store it in protected memory (see SodiumAlloc)
  randombytes_buf(key.data(), key_size);    // generate random bytes
  key.get_allocator().readonly(key.data()); // try to make key read-only

  // create a random nonce:
  data_t nonce(nonce_size); // store it in unprotected memory
  randombytes_buf(nonce.data(), nonce_size); // generate random bytes

  // encrypt the plaintext (binary blob) using key/nonce:
  data_t cyphertext = sc.encrypt(plainblob,  key, nonce);

  // (test-) decrypt the cyphertext using same key/nonce:
  data_t decrypted  = sc.decrypt(cyphertext, key, nonce);

  // we're done with the key for now, disable memory access to it!
  key.get_allocator().noaccess(key.data()); // try make key unread/unwriteable

  // should we need the key again here, we could make it readable
  // again with a call to key.get_allocator().readonly(key.data()),
  // as it is still in memory.
  //
  // the key will self-destruct and zero its storage though as soon
  // as the variable 'key' goes out of scope or test0() throws:
  // see SodiumAlloc::deallocate().

  // test of correctness (sanity check): the cyphertext must be
  // equal to the plaintext.
  // 
  // Note that SodiumCrypter::decrypt() will also have performed
  // a check and thrown a std::runtime_error, should the decryption
  // fail. It can detect corruption of the cyphertext, because
  // SodiumCrypter::encrypt() encrypts both the plaintext and a MAC
  // that was generated out of the plaintext and of the key/nonce before.
  //
  // We're just double-checking here.

  if (plainblob != decrypted)
    throw std::runtime_error {"test0() message forged (own test)"};

  // finally, convert the bytes of the cyphertext into a hexadecimal
  // string that can be printed, and return that string.

  std::string encrypted_as_hex = sc.tohex(cyphertext);
  return encrypted_as_hex;
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
  using data_t = SodiumCrypter::data_t; // unprotected memory
  using key_t  = SodiumCrypter::key_t;  // mprotect()ed memory for keys

  SodiumAuth sa {};

  // let's get the sizes in bytes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t mac_size        = crypto_auth_BYTES;
  std::size_t key_size        = crypto_auth_KEYBYTES;

  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // create a random key:
  key_t key(key_size); // store it in protected memory (see SodiumAlloc)
  randombytes_buf(key.data(), key_size);    // generate random bytes
  key.get_allocator().readonly(key.data()); // try to make key read-only

  // compute the MAC:
  data_t mac { sa.auth(plainblob, key) };

  // verify the MAC with unchanged data
  if (! sa.verify(plainblob, mac, key))
    throw std::runtime_error {"SodiumTester::test1() identical MAC failed"};

  // 2. change plaintext, and re-verify MAC:
  if (plainblob.size() > 0 &&
      (plainblob[0] = static_cast<unsigned char>('!')) &&
      sa.verify(plainblob, mac, key))
    throw std::runtime_error {"SodiumTester::test1() different MAC verify"};

  // 3. restore plaintext, then change key and reverify MAC
  plainblob.assign(plaintext.cbegin(), plaintext.cend());
  key.get_allocator().readwrite(key.data());
  key[0] = static_cast<unsigned char>('!');
  key.get_allocator().readonly(key.data());
  if (sa.verify(plainblob, mac, key))
    throw std::runtime_error {"SodiumTester::test1() different KEYS verify"};

  // not strictly necessary, because we're about to destroy key soon
  key.get_allocator().noaccess(key.data());

  return true;
}
