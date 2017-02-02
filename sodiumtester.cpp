// sodiumtester.cpp -- implementation of class SodiumTester

#include "sodiumtester.h"
#include "sodiumcrypter.h"

#include <stdexcept>
#include <string>
#include <algorithm>

SodiumTester::SodiumTester()
{
  if (sodium_init() == -1)
    throw std::runtime_error {"sodium_init() failed"};
}

std::string
SodiumTester::test0(const std::string &plaintext)
{
  using data_t = SodiumCrypter::data_t;
  using key_t  = SodiumCrypter::key_t;
  
  SodiumCrypter sc {};
  
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // transfer plaintext into a binary blob
  data_t plainblob {plaintext.cbegin(), plaintext.cend()};
  
  // get a random key and a random nonce
  key_t key(key_size);
  randombytes_buf(key.data(), key_size);
  key.get_allocator().readonly(key.data()); // try to make key read-only
  
  data_t nonce(nonce_size);
  randombytes_buf(nonce.data(), nonce_size);

  data_t encrypted = sc.encrypt(plainblob, key, nonce);
  data_t decrypted = sc.decrypt(encrypted, key, nonce);

  key.get_allocator().noaccess(key.data()); // try make key unread/unwriteable
  
  if (plainblob != decrypted)
    throw std::runtime_error {"test0() message forged (own test)"};

  std::string encrypted_as_hex = sc.tohex(encrypted);
  return encrypted_as_hex;
}
