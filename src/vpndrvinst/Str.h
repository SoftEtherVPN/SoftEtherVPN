#ifndef STR_H
#define STR_H

#include <stdbool.h>
#include <stddef.h>

#define MAC_BUFFER_SIZE 13

typedef struct _GUID GUID;

void GenMacAddress(char *dst, const size_t size);

const char *PathFileName(const char *path, const bool backslash);

void StrFromGUID(char *dst, const size_t size, const GUID *guid);

char *StrReplace(char *str, size_t *size, const char *target, const char *replacement, const bool shrink);

#endif
