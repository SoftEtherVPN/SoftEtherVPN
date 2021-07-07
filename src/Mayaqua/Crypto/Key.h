#ifndef CRYPTO_KEY_H
#define CRYPTO_KEY_H

#include "MayaType.h"

#define KEY_X25519_SIZE 32
#define KEY_X448_SIZE   56

enum CRYPTO_KEY_TYPE
{
	KEY_UNKNOWN,
	KEY_X25519,
	KEY_X448
};

struct CRYPTO_KEY_RAW
{
	BYTE *Data;
	UINT Size;
	CRYPTO_KEY_TYPE Type;
};

UINT CryptoKeyTypeSize(const CRYPTO_KEY_TYPE type);

CRYPTO_KEY_RAW *CryptoKeyRawNew(const void *data, const UINT size, const CRYPTO_KEY_TYPE type);
void CryptoKeyRawFree(CRYPTO_KEY_RAW *key);

CRYPTO_KEY_RAW *CryptoKeyRawPublic(const CRYPTO_KEY_RAW *private);
void *CryptoKeyRawToOpaque(const CRYPTO_KEY_RAW *key, const bool public);

void *CryptoKeyOpaqueNew(const CRYPTO_KEY_TYPE type);
void CryptoKeyOpaqueFree(void *key);

bool CryptoKeyOpaqueToRaw(const void *opaque, CRYPTO_KEY_RAW **private, CRYPTO_KEY_RAW **public);

#endif
