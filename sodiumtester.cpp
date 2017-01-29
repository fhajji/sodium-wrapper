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

  // put [cypherbuf, cypherbuf+plaintext.size()] into cyphertext
  std::string cyphertext {cypherbuf.get(),
      cypherbuf.get() + cyphertext_size + 1 };

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
  
  return cyphertext;
}
