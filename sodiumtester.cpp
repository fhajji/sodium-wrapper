// sodiumtester.cpp -- Test functions for the test harness SodiumTester
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#include "sodiumtester.h"

#include "sodiumkey.h"
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
 * - We use Sodium::Key wrapper to create and store a random key in mprotect()
 * - We use libsodium's randombytes_buf() to generate random nonce
 * - We store the plaintext/ciphertext in a data_t, which is unprotected
 * - We use our wrapper SodiumCrypter to do the encryption
 * - We use our wrapper SodiumCrypter to test-decrypt the result
 *   and verify that the decrypted text is the same as the plaintext.
 * - We use our wrapper SodiumCrypter to convert the ciphertext into
 *   hexadecimal string, which we return.
 **/

std::string
SodiumTester::test0(const std::string &plaintext)
{  
  using data_t = SodiumCrypter::data_t; // unprotected memory
  
  SodiumCrypter sc {}; // encryptor, decryptor, hexifior.
  Sodium::Key   key(Sodium::Key::KEYSIZE_SECRETBOX);
  
  // let's get the sizes in bytes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t ciphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = key.size();
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // create a random nonce:
  data_t nonce(nonce_size); // store it in unprotected memory
  randombytes_buf(nonce.data(), nonce_size); // generate random bytes

  // encrypt the plaintext (binary blob) using key/nonce:
  data_t ciphertext = sc.encrypt(plainblob,  key, nonce);

  // (test-) decrypt the ciphertext using same key/nonce:
  data_t decrypted  = sc.decrypt(ciphertext, key, nonce);

  // we're done with the key for now, disable memory access to it!
  key.noaccess();
  
  // test of correctness (sanity check): the ciphertext must be
  // equal to the plaintext.
  // 
  // Note that SodiumCrypter::decrypt() will also have performed
  // a check and thrown a std::runtime_error, should the decryption
  // fail. It can detect corruption of the ciphertext, because
  // SodiumCrypter::encrypt() encrypts both the plaintext and a MAC
  // that was generated out of the plaintext and of the key/nonce before.
  //
  // We're just double-checking here.

  if (plainblob != decrypted)
    throw std::runtime_error {"test0() message forged (own test)"};

  // finally, convert the bytes of the ciphertext into a hexadecimal
  // string that can be printed, and return that string.

  std::string encrypted_as_hex = sc.tohex(ciphertext);
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
  using data_t = SodiumAuth::data_t; // unprotected memory
  
  SodiumAuth  sa {};
  Sodium::Key key(Sodium::Key::KEYSIZE_AUTH);
  
  // let's get the sizes in bytes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t mac_size        = crypto_auth_BYTES;
  std::size_t key_size        = key.size();
  
  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
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
  key.readwrite();
  key.initialize();
  key.readonly();
  if (sa.verify(plainblob, mac, key))
    throw std::runtime_error {"SodiumTester::test1() different KEYS verify"};

  // not strictly necessary, because we're about to destroy key soon
  key.noaccess();

  return true;
}

/**
 * This function tests the key derivation algorithm of libsodium.
 *
 * 1/ Derive a key from a user-entered password, and encrypt plaintext
 * with it.
 * 2/ Re-ask user for password, derive new key from that, and
 * decrypt encrypted text with the new key.
 * 3/ See if we can decrypt the encrypted plaintext this way.
 **/

bool
SodiumTester::test2(const std::string &plaintext,
		    const std::string &pw1,
		    const std::string &pw2)
{
  using data_t = SodiumCrypter::data_t; // unprotected memory
  using key_t  = Sodium::Key::key_t;    // protected memory
  
  SodiumCrypter sc {}; // encryptor, decryptor, hexifior.
  Sodium::Key   key(Sodium::Key::KEYSIZE_SECRETBOX,
		    false); // uninitialized, read-write for now
  key_t         keybuf(Sodium::Key::KEYSIZE_SECRETBOX);
  
  data_t salt(crypto_pwhash_SALTBYTES);
  randombytes_buf(salt.data(), salt.size());

  // let's get the sizes in bytes
  std::size_t plaintext_size  = plaintext.size();
  std::size_t ciphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = key.size();
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;
  std::size_t salt_size       = salt.size();

  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};

  // create a random nonce:
  data_t nonce(nonce_size); // store it in unprotected memory
  randombytes_buf(nonce.data(), nonce_size); // generate random bytes

  // transfer user-supplied passwords into binary blobs
  std::vector<char> pw1blob {pw1.cbegin(), pw1.cend()}; // XXX key_t?
  std::vector<char> pw2blob {pw2.cbegin(), pw2.cend()}; // XXX key_t?
  
  // derive a key from the hash of first passwd into keybuf.data():
  if (crypto_pwhash (keybuf.data(), keybuf.size(),
		     pw1blob.data(), pw1blob.size(),
		     salt.data(),
		     crypto_pwhash_OPSLIMIT_INTERACTIVE,
		     crypto_pwhash_MEMLIMIT_INTERACTIVE,
		     crypto_pwhash_ALG_DEFAULT) != 0)
    throw std::runtime_error {"SodiumTester::test2() crypto_pwhash() #1"};

  // transfer the keybuf into our key object
  key.setkey(keybuf.data(), keybuf.size());

  // now encrypt with that key
  data_t ciphertext = sc.encrypt(plainblob, key, nonce);

  // derive a key from the hash of second passwd into keybuf.data()
  if (crypto_pwhash (keybuf.data(), keybuf.size(),
		     pw2blob.data(), pw2blob.size(),
		     salt.data(),
		     crypto_pwhash_OPSLIMIT_INTERACTIVE,
		     crypto_pwhash_MEMLIMIT_INTERACTIVE,
		     crypto_pwhash_ALG_DEFAULT) != 0)
    throw std::runtime_error {"SodiumTester::test2() crypto_pwhash() #2"};
  
  // transfer the keybuf into our key object
  key.setkey(keybuf.data(), keybuf.size());

  // now decrypt with that new key.
  // if the key/password was different, we will throw right here and now
  data_t decrypted = sc.decrypt(ciphertext, key, nonce);

  return (decrypted == plainblob);
}
