// sodiumcrypter.cpp -- implements SodiumCrypter class

#include "sodiumcrypter.h"

#include <stdexcept>
#include <string>
#include <algorithm>
#include <memory>

#include <sodium.h>

template <typename T>
using uniquePtr = std::unique_ptr<T,void(*)(T*)>;

std::string
SodiumCrypter::encrypt (const std::string &plaintext,
		        const std::string &key,
		        const std::string &nonce)
{
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // some sanity checks
  if (key.size() != key_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() key has wrong size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() nonce has wrong size"};
  
  // copy the bytes of the plaintext into a buffer of unsigned char bytes
  uniquePtr<unsigned char> plainbuf(new unsigned char[plaintext_size],
				    [](unsigned char *p) { delete[] p; });
  std::copy (plaintext.cbegin(), plaintext.cend(), plainbuf.get());

  // copy the bytes of the key into a buffer of unsigned char bytes
  uniquePtr<unsigned char> keybuf(new unsigned char[key_size],
				  [](unsigned char *p) { delete[] p; });
  std::copy (key.cbegin(), key.cend(), keybuf.get());

  // copy the bytes of the nonce into a buffer of unsigned char bytes
  uniquePtr<unsigned char> noncebuf(new unsigned char[nonce_size],
				    [](unsigned char *p) { delete[] p; });
  std::copy (nonce.cbegin(), nonce.cend(), noncebuf.get());

  // make space for MAC and encrypted message
  uniquePtr<unsigned char> cypherbuf(new unsigned char[cyphertext_size],
				     [](unsigned char *p) { delete[] p; });

  // let's encrypt now!
  crypto_secretbox_easy (cypherbuf.get(),
			 plainbuf.get(), plaintext_size,
			 noncebuf.get(),
			 keybuf.get());

  // copy output bytes into string
  std::string cyphertext {cypherbuf.get(),
      cypherbuf.get() + cyphertext_size};

  return cyphertext;
}

std::string
SodiumCrypter::decrypt (const std::string &cyphertext,
		        const std::string &key,
		        const std::string &nonce)
{
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t key_size        = key.size();
  std::size_t nonce_size      = nonce.size();
  std::size_t plaintext_size  = cyphertext_size - crypto_secretbox_MACBYTES;
  
  // some sanity checks
  if (key_size != crypto_secretbox_KEYBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() key has wrong size"};
  if (nonce_size != crypto_secretbox_NONCEBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() nonce has wrong size"};
  if (plaintext_size <= 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() plaintext negative size"};
  
  // copy the bytes of the cyphertext into a buffer of unsigned char bytes
  uniquePtr<unsigned char> cypherbuf(new unsigned char[cyphertext_size],
				     [](unsigned char *p) { delete[] p; });
  std::copy (cyphertext.cbegin(), cyphertext.cend(), cypherbuf.get());

  // copy the bytes of the key into a buffer of unsigned char bytes
  uniquePtr<unsigned char> keybuf(new unsigned char[key_size],
				  [](unsigned char *p) { delete[] p; });
  std::copy (key.cbegin(), key.cend(), keybuf.get());

  // copy the bytes of the nonce into a buffer of unsigned char bytes
  uniquePtr<unsigned char> noncebuf(new unsigned char[key_size],
				    [](unsigned char *p) { delete[] p; });
  std::copy (nonce.cbegin(), nonce.cend(), noncebuf.get());

  // make space for decrypted buffer
  uniquePtr<unsigned char> decryptbuf(new unsigned char[plaintext_size],
				      [](unsigned char *p) { delete[] p; });

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptbuf.get(),
				  cypherbuf.get(), cyphertext_size,
				  noncebuf.get(),
				  keybuf.get()) != 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() message forged (sodium test)"};

  // copy result into string and return

  std::string plaintext { decryptbuf.get(),
      decryptbuf.get() + plaintext_size};

  return plaintext;
}

std::string
SodiumCrypter::tohex (const std::string &cyphertext)
{
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t hex_size        = cyphertext_size * 2 + 1;

  // copy bytes in cyphertext into buffer of unsigned char bytes
  uniquePtr<unsigned char> cypherbuf(new unsigned char[cyphertext_size],
				     [](unsigned char *p) { delete[] p; });
  std::copy (cyphertext.cbegin(), cyphertext.cend(), cypherbuf.get());
  
  // convert [cypherbuf, cypherbuf + cyphertext_size] into hex:
  uniquePtr<char> hexbuf(new char[hex_size],
			 [](char *p) { delete[] p; });
  if (! sodium_bin2hex(hexbuf.get(), hex_size,
		       cypherbuf.get(), cyphertext_size))
    throw std::runtime_error {"SodiumCrypter::tohex() overflowed"};

  // return hex output as a string:
  std::string outhex {hexbuf.get(), hexbuf.get() + hex_size};
  return outhex;
}
