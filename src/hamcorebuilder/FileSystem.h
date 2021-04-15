#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <stdbool.h>

#include <tinydir.h>

#define MAX_PATH_LENGTH _TINYDIR_PATH_MAX

typedef struct ENTRY
{
	bool IsDir;
	char Path[MAX_PATH_LENGTH];
} ENTRY;

typedef struct ENTRIES
{
	size_t Num;
	ENTRY *List;
} ENTRIES;

ENTRIES *EnumEntries(const char *path);
ENTRIES *EnumEntriesRecursively(const char *path, const bool files_only);
void FreeEntries(ENTRIES *entries);

#ifndef OS_WINDOWS
bool IsWindowsExtension(const char *extension);
#endif

#endif
