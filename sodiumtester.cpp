// sodiumtester.cpp -- implementation of class SodiumTester

#include "sodiumtester.h"

#include <stdexcept>
#include <string>
#include <algorithm>
#include <memory>

#include <sodium.h>

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
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;
  
  // copy the bytes of the plaintext into a buffer of unsigned char bytes
  uniquePtr<unsigned char> plainbuf(new unsigned char[plaintext_size],
				    [](unsigned char *p) { delete[] p; });
  std::copy (plaintext.cbegin(), plaintext.cend(), plainbuf.get());
    
  // get a random key and a random nonce
  unsigned char key[key_size];
  randombytes_buf(key, sizeof key);
  unsigned char nonce[nonce_size];
  randombytes_buf(nonce, sizeof nonce);

  // make space for MAC and encrypted message
  uniquePtr<unsigned char> cypherbuf(new unsigned char[cyphertext_size],
				     [](unsigned char *p) { delete[] p; });

  // let's encrypt now!
  crypto_secretbox_easy (cypherbuf.get(),
			 plainbuf.get(), plaintext_size,
			 nonce,
			 key);

  // proof of correctness: let's try to decrypt!
  uniquePtr<unsigned char> decryptbuf(new unsigned char[plaintext_size],
				      [](unsigned char *p) { delete[] p; });
  if (crypto_secretbox_open_easy (decryptbuf.get(),
				  cypherbuf.get(), cyphertext_size,
				  nonce, key) != 0)
    throw std::runtime_error {"test0() message forged (sodium test)"};

  if (! std::equal (plainbuf.get(), plainbuf.get() + plaintext_size + 1,
		    decryptbuf.get()))
    throw std::runtime_error {"test0() message forged (own test)"};

  // convert [cypherbuf, cypherbuf+cyphertext_size] into hex:
  std::size_t hex_size = cyphertext_size * 2 + 1;
  uniquePtr<char> hexbuf(new char[hex_size],
			 [](char *p) { delete[] p; });
  if (! sodium_bin2hex(hexbuf.get(), hex_size,
		       cypherbuf.get(), cyphertext_size))
    throw std::runtime_error {"test0() sodium_bin2hex() overflowed"};

  // return hex output as a string:
  std::string cyphertext {hexbuf.get(), hexbuf.get() + hex_size + 1};
  return cyphertext;

  // all buffers allocated with new[] will be automatically delete[]ed
  // upon return or when this function throws because we've used
  // unique_ptr<> and used deleters.
}
