#include "Encoding.h"

#include <math.h>

#include <openssl/evp.h>

UINT Base64Decode(void *dst, const void *src, const UINT size)
{
	if (dst == NULL)
	{
		// 4 input bytes = max. 3 output bytes.
		//
		// EVP_DecodeUpdate() ignores:
		// - Leading/trailing whitespace.
		// - Trailing newlines, carriage returns or EOF characters.
		//
		// EVP_DecodeFinal() fails if the input is not divisible by 4.
		return size / 4 * 3;
	}

	// We don't use EVP_DecodeBlock() because it adds padding if the output is not divisible by 3.
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	if (ctx == NULL)
	{
		return 0;
	}

	int ret = 0;
	if (EVP_DecodeUpdate(ctx, dst, &ret, src, size) < 0)
	{
		goto FINAL;
	}

	int dummy;
	if (EVP_DecodeFinal(ctx, dst, &dummy) < 0)
	{
		ret = 0;
	}
FINAL:
	EVP_ENCODE_CTX_free(ctx);
	return ret;
}

UINT Base64Encode(void *dst, const void *src, const UINT size)
{
	if (dst == NULL)
	{
		// 3 input bytes = 4 output bytes.
		// +1 for the NUL terminator.
		//
		// EVP_EncodeBlock() adds padding when the input is not divisible by 3.
		return ceilf((float)size / 3) * 4 + 1;
	}

	const int ret = EVP_EncodeBlock(dst, src, size);
	if (ret > 0)
	{
		// EVP_EncodeBlock() returns the length of the string without the NUL terminator.
		// We, instead, want to return the amount of bytes written into the output buffer.
		return ret + 1;
	}

	return 0;
}
