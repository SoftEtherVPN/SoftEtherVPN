#include "Str.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <guiddef.h>

void GenMacAddress(char *dst, const size_t size)
{
	if (!dst || size == 0)
	{
		return;
	}

	srand((unsigned int)time(NULL));

	uint8_t mac[6];
	mac[0] = 0x5E;
	mac[1] = rand() % 256;
	mac[2] = rand() % 256;
	mac[3] = rand() % 256;
	mac[4] = rand() % 256;
	mac[5] = rand() % 256;

	snprintf(dst, size, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *PathFileName(const char *path, const bool backslash)
{
	if (!path)
	{
		return NULL;
	}

	const char *ret = strrchr(path, backslash ? '\\' : '/');
	if (ret)
	{
		++ret;
	}

	return ret;
}

void StrFromGUID(char *dst, const size_t size, const GUID *guid)
{
	if (!dst || size == 0 || !guid)
	{
		return;
	}

	snprintf(dst, size, "{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

char *StrReplace(char *str, size_t *size, const char *target, const char *replacement, const bool shrink)
{
	if (!str || !size || !target || !replacement)
	{
		return str;
	}

	const char *seek = str;

	size_t str_len = strlen(str);
	const size_t target_len = strlen(target);
	const size_t replacement_len = strlen(replacement);

	char *at_target;
	while ((at_target = strstr(seek, target)))
	{
		size_t new_str_len = str_len;

		if (target_len > replacement_len)
		{
			new_str_len -= target_len - replacement_len;
		}
		else
		{
			new_str_len += replacement_len - target_len;
			const size_t required_size = new_str_len + 1;
			if (*size < required_size)
			{
				const char *old_str = str;

				*size = required_size;
				str = realloc(str, *size);
				seek = str + (seek - old_str);
				at_target = str + (at_target - old_str);
			}
		}

		const char *after_target = at_target + target_len;
		memmove(at_target + replacement_len, after_target, str_len - (after_target - seek) + 1);
		memcpy(at_target, replacement, replacement_len);

		str_len = new_str_len;
	}

	if (shrink && *size > str_len + 1)
	{
		*size = str_len + 1;
		str = realloc(str, *size);
	}

	return str;
}
