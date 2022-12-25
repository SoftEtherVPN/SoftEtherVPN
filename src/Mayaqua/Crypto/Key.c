#include "Key.h"

#include "Encrypt.h"
#include "Memory.h"
#include "Str.h"

#include <openssl/evp.h>

static int CryptoKeyTypeToID(const CRYPTO_KEY_TYPE type)
{
	switch (type)
	{
		case KEY_UNKNOWN:
			break;
		case KEY_X25519:
			return EVP_PKEY_X25519;
#if defined(EVP_PKEY_X448)
		case KEY_X448:
			return EVP_PKEY_X448;
#endif
		default:
			Debug("CryptoKeyTypeToID(): Unhandled type %u!\n", type);
	}

	return EVP_PKEY_NONE;
}

UINT CryptoKeyTypeSize(const CRYPTO_KEY_TYPE type)
{
	switch (type)
	{
		case KEY_UNKNOWN:
			break;
		case KEY_X25519:
			return KEY_X25519_SIZE;
		case KEY_X448:
			return KEY_X448_SIZE;
		default:
			Debug("CryptoKeyTypeSize(): Unhandled type %u!\n", type);
	}

	return 0;
}

CRYPTO_KEY_RAW *CryptoKeyRawNew(const void *data, const UINT size, const CRYPTO_KEY_TYPE type)
{
	if (size == 0 || size != CryptoKeyTypeSize(type))
	{
		return NULL;
	}

	CRYPTO_KEY_RAW *key = Malloc(sizeof(CRYPTO_KEY_RAW));
	key->Data = MallocEx(size, true);
	key->Size = size;
	key->Type = type;

	if (data == NULL)
	{
		Rand(key->Data, key->Size);
	}
	else
	{
		Copy(key->Data, data, key->Size);
	}

	return key;
}

void CryptoKeyRawFree(CRYPTO_KEY_RAW *key)
{
	if (key == NULL)
	{
		return;
	}

	Free(key->Data);
	Free(key);
}

CRYPTO_KEY_RAW *CryptoKeyRawPublic(const CRYPTO_KEY_RAW *private)
{
	if (private == NULL)
	{
		return NULL;
	}

	void *opaque = CryptoKeyRawToOpaque(private, false);
	if (opaque == NULL)
	{
		return NULL;
	}

	CRYPTO_KEY_RAW *public = NULL;
	CryptoKeyOpaqueToRaw(opaque, NULL, &public);
	CryptoKeyOpaqueFree(opaque);

	return public;
}

void *CryptoKeyRawToOpaque(const CRYPTO_KEY_RAW *key, const bool public)
{
	if (key == NULL)
	{
		return NULL;
	}

	const int id = CryptoKeyTypeToID(key->Type);

	if (public)
	{
		return EVP_PKEY_new_raw_public_key(id, NULL, key->Data, key->Size);
	}
	else
	{
		return EVP_PKEY_new_raw_private_key(id, NULL, key->Data, key->Size);
	}
}

void *CryptoKeyOpaqueNew(const CRYPTO_KEY_TYPE type)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(CryptoKeyTypeToID(type), NULL);
	if (ctx == NULL)
	{
		Debug("CryptoKeyOpaqueNew(): EVP_PKEY_CTX_new_id() returned NULL!\n");
		return false;
	}

	EVP_PKEY *key = NULL;

	int ret = EVP_PKEY_keygen_init(ctx);
	if (ret != 1)
	{
		Debug("CryptoKeyOpaqueNew(): EVP_PKEY_keygen_init() returned %d!\n", ret);
		goto FINAL;
	}

	ret = EVP_PKEY_keygen(ctx, &key);
	if (ret != 1)
	{
		Debug("CryptoKeyOpaqueNew(): EVP_PKEY_keygen() returned %d!\n", ret);
	}
FINAL:
	EVP_PKEY_CTX_free(ctx);
	return key;
}

void CryptoKeyOpaqueFree(void *key)
{
	if (key != NULL)
	{
		EVP_PKEY_free(key);
	}
}

bool CryptoKeyOpaqueToRaw(const void *opaque, CRYPTO_KEY_RAW **private, CRYPTO_KEY_RAW **public)
{
	if (opaque == NULL || (private == NULL && public == NULL))
	{
		return false;
	}

	CRYPTO_KEY_TYPE type;

	switch (EVP_PKEY_id(opaque))
	{
	case EVP_PKEY_X25519:
		type = KEY_X25519;
		break;
#if defined(EVP_PKEY_X448)
	case EVP_PKEY_X448:
		type = KEY_X448;
		break;
#endif
	default:
		return false;
	}

	if (private != NULL)
	{
		size_t size;
		int ret = EVP_PKEY_get_raw_private_key(opaque, NULL, &size);
		if (ret != 1)
		{
			Debug("CryptoKeyOpaqueToRaw(): #1 EVP_PKEY_get_raw_private_key() returned %d!\n", ret);
			return false;
		}

		CRYPTO_KEY_RAW *key = CryptoKeyRawNew(NULL, size, type);

		ret = EVP_PKEY_get_raw_private_key(opaque, key->Data, &size);
		if (ret != 1)
		{
			Debug("CryptoKeyOpaqueToRaw(): #2 EVP_PKEY_get_raw_private_key() returned %d!\n", ret);
			CryptoKeyRawFree(key);
			return false;
		}

		*private = key;
	}

	if (public != NULL)
	{
		size_t size;
		int ret = EVP_PKEY_get_raw_public_key(opaque, NULL, &size);
		if (ret != 1)
		{
			Debug("CryptoKeyOpaqueToRaw(): #1 EVP_PKEY_get_raw_public_key() returned %d!\n", ret);
			return false;
		}

		CRYPTO_KEY_RAW *key = CryptoKeyRawNew(NULL, size, type);

		ret = EVP_PKEY_get_raw_public_key(opaque, key->Data, &size);
		if (ret != 1)
		{
			Debug("CryptoKeyOpaqueToRaw(): #2 EVP_PKEY_get_raw_public_key() returned %d!\n", ret);
			CryptoKeyRawFree(key);
			return false;
		}

		*public = key;
	}

	return true;
}
