#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <stdbool.h>
#include <stdio.h>

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

FILE *FileOpen(const char *path, const bool write);
bool FileClose(FILE *file);
bool FileRead(FILE *file, void *dst, const size_t size);
bool FileWrite(FILE *file, const void *src, const size_t size);
size_t FileSize(const char *path);

char *PathRelativeToBase(char *full, const char *base);

#ifndef OS_WINDOWS
bool IsWindowsExtension(const char *extension);
#endif

#endif
