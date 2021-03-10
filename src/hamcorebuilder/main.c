#include "FileSystem.h"

#include "Hamcore.h"

int main(const int argc, const char *argv[])
{
	printf("hamcore.se2 builder\n\n");

	if (argc < 3)
	{
		printf("Usage: hamcorebuilder <dest_file> <src_dir>\n\n");
		return 0;
	}

	const char *dst = argv[1];
	const char *src = argv[2];

	printf("Destination: \"%s\"\n", dst);
	printf("Source: \"%s\"\n\n", src);

	ENTRIES *entries = EnumEntriesRecursively(src, true);
	if (!entries)
	{
		return 1;
	}

	const size_t num = entries->Num;
	char **paths = malloc(sizeof(char *) * num);

	for (size_t i = 0; i < num; ++i)
	{
		const ENTRY *entry = &entries->List[i];
		const size_t path_len = strlen(entry->Path);
		paths[i] = malloc(path_len + 1);
		memcpy(paths[i], entry->Path, path_len + 1);
	}

	FreeEntries(entries);

	const bool ok = HamcoreBuild(dst, src, (const char **)paths, num);

	for (size_t i = 0; i < num; ++i)
	{
		free(paths[i]);
	}

	free(paths);

	if (!ok)
	{
		return 2;
	}

	printf("Done!\n");
	return 0;
}
