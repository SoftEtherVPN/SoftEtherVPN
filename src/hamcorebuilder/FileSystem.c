#include "FileSystem.h"

#include <stdio.h>

ENTRIES *EnumEntries(const char *path)
{
	if (!path)
	{
		return NULL;
	}

	tinydir_dir dir;
	if (tinydir_open_sorted(&dir, path) == -1)
	{
		printf("tinydir_open_sorted() failed!\n");
		return NULL;
	}

	ENTRIES *entries = calloc(1, sizeof(ENTRIES));

	for (size_t i = 0; i < dir.n_files; ++i)
	{
		tinydir_file file;
		if (tinydir_readfile_n(&dir, &file, i) == -1)
		{
			printf("tinydir_readfile_n() failed at index %zu!\n", i);
			FreeEntries(entries);
			return NULL;
		}

		if (file.is_dir)
		{
			if (strcmp(file.name, ".") == 0 || strcmp(file.name, "..") == 0)
			{
				continue;
			}
		}
#ifndef OS_WINDOWS
		if (IsWindowsExtension(file.extension))
		{
			continue;
		}
#endif
		++entries->Num;
		entries->List = realloc(entries->List, sizeof(ENTRY) * entries->Num);

		ENTRY *entry = &entries->List[entries->Num - 1];
		entry->IsDir = file.is_dir;
		strcpy(entry->Path, file.path);
	}

	tinydir_close(&dir);
	return entries;
}

ENTRIES *EnumEntriesRecursively(const char *path, const bool files_only)
{
	if (!path)
	{
		return NULL;
	}

	ENTRIES *tmp = EnumEntries(path);
	if (!tmp)
	{
		return NULL;
	}

	ENTRIES *entries = calloc(1, sizeof(ENTRIES));

	for (size_t i = 0; i < tmp->Num; ++i)
	{
		ENTRY *entry = &tmp->List[i];
		if (!files_only || !entry->IsDir)
		{
			++entries->Num;
			entries->List = realloc(entries->List, sizeof(ENTRY) * entries->Num);
			memcpy(&entries->List[entries->Num - 1], entry, sizeof(ENTRY));
		}

		if (!entry->IsDir)
		{
			continue;
		}

		ENTRIES *tmp_2 = EnumEntries(entry->Path);
		if (!tmp_2)
		{
			continue;
		}

		const size_t offset = tmp->Num;

		tmp->Num += tmp_2->Num;
		tmp->List = realloc(tmp->List, sizeof(ENTRY) * tmp->Num);

		memcpy(&tmp->List[offset], tmp_2->List, sizeof(ENTRY) * tmp_2->Num);

		FreeEntries(tmp_2);
	}

	FreeEntries(tmp);

	return entries;
}

void FreeEntries(ENTRIES *entries)
{
	if (!entries)
	{
		return;
	}

	if (entries->List)
	{
		free(entries->List);
	}

	free(entries);
}

#ifndef OS_WINDOWS
bool IsWindowsExtension(const char *extension)
{
	if (!extension)
	{
		return false;
	}

	if (strcmp(extension, "cat") == 0 ||
		strcmp(extension, "dll") == 0 ||
		strcmp(extension, "exe") == 0 ||
		strcmp(extension, "inf") == 0 ||
		strcmp(extension, "sys") == 0)
	{
		return true;
	}

	return false;
}
#endif
