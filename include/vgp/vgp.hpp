// Copyright (c) 2021 Duality Blockchain Solutions LLC
// See LICENSE.md file for license, copying and use information.

#ifndef VGP_HEADER_H__
#define VGP_HEADER_H__

#include "../encryption.h"

namespace VGP {
bool Encrypt(const vCharVector& vchPubKeys, const CharVector& vchData, CharVector& vchCipherText, std::string& strErrorMessage) {
 	return EncryptBDAPData(vchPubKeys, vchData, vchCipherText, strErrorMessage);
}

bool Decrypt(const CharVector& vchPrivKeySeed, const CharVector& vchCipherText, CharVector& vchData, std::string& strErrorMessage) {
	return DecryptBDAPData(vchPrivKeySeed, vchCipherText, vchData, strErrorMessage);
}
}

#endif // VGP_HEADER_H__
