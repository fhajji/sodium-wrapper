// sodiumtester.cpp -- implementation of class SodiumTester

#include "sodiumtester.h"
#include "sodiumcrypter.h"

#include <stdexcept>
#include <string>
#include <algorithm>
#include <memory>

#include <sodium.h>

// DEBUG
#include <iostream>

template <typename T>
using uniquePtr = std::unique_ptr<T,void(*)(T*)>; // alias template

SodiumTester::SodiumTester()
{
  if (sodium_init() == -1)
    throw std::runtime_error {"sodium_init() failed"};
}

std::string
SodiumTester::test0(const std::string &plaintext)
{
  SodiumCrypter sc {};

  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;
      
  // get a random key and a random nonce
  unsigned char key[key_size];
  randombytes_buf(key, sizeof key);
  unsigned char nonce[nonce_size];
  randombytes_buf(nonce, sizeof nonce);

  std::string keystring {key, key + key_size}; // beg, end
  std::string noncestring {nonce, nonce + nonce_size}; // beg, end

  // DEBUG
  std::string keystring_as_hex = sc.tohex(keystring);
  std::string noncestring_as_hex = sc.tohex(noncestring);
  std::cerr << "DEBUG: key   is: " << keystring_as_hex << std::endl;
  std::cerr << "DEBUG: nonce is: " << noncestring_as_hex << std::endl;
  std::cerr << "DEBUG: key_size is: " << keystring.size() << std::endl;
  std::cerr << "DEBUG: key_size should be: " << key_size  << std::endl;
  
  std::string encrypted = sc.encrypt(plaintext, keystring, noncestring);

  // DEBUG
  std::string encrypted_as_hex2 = sc.tohex(encrypted);
  std::cout << "DEBUG: encrypted=" << encrypted_as_hex2 << std::endl;
  
  std::string decrypted = sc.decrypt(encrypted, keystring, noncestring);
  
  if (plaintext != decrypted)
    throw std::runtime_error {"test0() message forged (own test)"};

  std::string encrypted_as_hex = sc.tohex(encrypted);

  return encrypted_as_hex;
}
