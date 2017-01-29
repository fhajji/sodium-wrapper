// sodiumcrypter.h -- symmetric encryption/decryption with MAC class

#ifndef _SODIUMCRYPTER_H_
#define _SODIUMCRYPTER_H_

#include <string>

class SodiumCrypter
{
 public:
  std::string encrypt(const std::string &plaintext,
		      const std::string &key,
		      const std::string &nonce);

  std::string decrypt(const std::string &cyphertext,
		      const std::string &key,
		      const std::string &nonce);

  std::string tohex(const std::string &cyphertext);
};

#endif // _SODIUMCRYPTER_H_
