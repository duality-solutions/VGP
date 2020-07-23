#include "libvgp.h"

bool Encrypt(const vCharVector& vchPubKeys, const CharVector& vchData, CharVector& vchCipherText, std::string& strErrorMessage)
{
	return EncryptBDAPData(vchPubKeys, vchData, vchCipherText, strErrorMessage);
}

bool Decrypt(const CharVector& vchPrivKeySeed, const CharVector& vchCipherText, CharVector& vchData, std::string& strErrorMessage)
{
	return DecryptBDAPData(vchPrivKeySeed, vchCipherText, vchData, strErrorMessage);
}
