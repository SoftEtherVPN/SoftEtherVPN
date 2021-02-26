#include "GlobalConst.h"

#include "FileSystem.h"

#include <stdint.h>

#include <zlib.h>

#ifdef BYTE_ORDER_BIG_ENDIAN
#	define BigEndian32
#else
#	define BigEndian32 Swap32
#endif

typedef struct CompressedFile
{
	char *Path;
	uint8_t *Data;
	size_t Size;
	size_t OriginalSize;
	size_t Offset;
} CompressedFile;

size_t CompressionBufferSize(const size_t original_size)
{
	return original_size * 2 + 256;
}

uint32_t Swap32(const uint32_t value)
{
	uint32_t swapped;
	((uint8_t *)&swapped)[0] = ((uint8_t *)&value)[3];
	((uint8_t *)&swapped)[1] = ((uint8_t *)&value)[2];
	((uint8_t *)&swapped)[2] = ((uint8_t *)&value)[1];
	((uint8_t *)&swapped)[3] = ((uint8_t *)&value)[0];
	return swapped;
}

void WriteAndSeek(uint8_t **dst, const void *src, const size_t size)
{
	if (!dst || !*dst)
	{
		return;
	}

	memcpy(*dst, src, size);
	*dst += size;
}

bool BuildHamcore(const char *dst, const char *src)
{
	ENTRIES *entries = EnumEntriesRecursively(src, true);
	if (!entries)
	{
		return false;
	}

	uint8_t *buffer = NULL;
	size_t buffer_size = 0;
	const size_t num = entries->Num;
	CompressedFile *files = calloc(num, sizeof(CompressedFile));

	for (size_t i = 0; i < num; ++i)
	{
		CompressedFile *file = &files[i];
		char *path = entries->List[i].Path;

		file->OriginalSize = FileSize(path);
		if (file->OriginalSize == 0)
		{
			printf("Skipping \"%s\" because empty...\n", path);
			continue;
		}

		FILE *handle = FileOpen(path, false);
		if (!handle)
		{
			printf("Failed to open \"%s\", skipping...\n", path);
			continue;
		}

		uint8_t *content = malloc(file->OriginalSize);
		if (!FileRead(handle, content, file->OriginalSize))
		{
			printf("FileRead() failed for \"%s\", skipping...\n", path);
			free(content);
			continue;
		}

		FileClose(handle);

		const size_t wanted_size = CompressionBufferSize(file->OriginalSize);
		if (buffer_size < wanted_size)
		{
			const size_t prev_size = buffer_size;
			buffer_size = wanted_size;
			buffer = realloc(buffer, buffer_size);
			memset(buffer + prev_size, 0, buffer_size - prev_size);
		}

		file->Size = buffer_size;
		const int ret = compress(buffer, (uLongf *)&file->Size, content, (uLong)file->OriginalSize);
		free(content);

		if (ret != Z_OK)
		{
			printf("Failed to compress \"%s\" with error %d, skipping...\n", path, ret);
			file->Size = 0;
			continue;
		}

		char *relative_path = PathRelativeToBase(path, src);
		if (!relative_path)
		{
			printf("Failed to get relative path for \"%s\", skipping...\n", path);
			file->Size = 0;
			continue;
		}

		const size_t path_size = strlen(relative_path) + 1;
		file->Path = malloc(path_size);
		memcpy(file->Path, relative_path, path_size);

		file->Data = malloc(file->Size);
		memcpy(file->Data, buffer, file->Size);

		printf("\"%s\": %zu bytes -> %zu bytes\n", file->Path, file->OriginalSize, file->Size);
	}

	FreeEntries(entries);

	size_t offset = HAMCORE_HEADER_SIZE;
	// Number of files
	offset += sizeof(uint32_t);
	// File table
	for (size_t i = 0; i < num; ++i)
	{
		CompressedFile *file = &files[i];
		if (file->Size == 0)
		{
			continue;
		}

		// Path (length + string)
		offset += sizeof(uint32_t) + strlen(file->Path);
		// Original size
		offset += sizeof(uint32_t);
		// Size
		offset += sizeof(uint32_t);
		// Offset
		offset += sizeof(uint32_t);
	}

	for (size_t i = 0; i < num; ++i)
	{
		CompressedFile *file = &files[i];
		if (file->Size == 0)
		{
			continue;
		}

		file->Offset = offset;
		printf("Offset for \"%s\": %zu\n", file->Path, file->Offset);
		offset += file->Size;
	}

	if (buffer_size < offset)
	{
		buffer_size = offset;
		buffer = realloc(buffer, buffer_size);
	}

	uint8_t *ptr = buffer;
	WriteAndSeek(&ptr, HAMCORE_HEADER_DATA, HAMCORE_HEADER_SIZE);
	uint32_t tmp = BigEndian32((uint32_t)num);
	WriteAndSeek(&ptr, &tmp, sizeof(tmp));

	for (size_t i = 0; i < num; ++i)
	{
		CompressedFile *file = &files[i];
		if (file->Size == 0)
		{
			continue;
		}

		const size_t path_length = strlen(file->Path);
		tmp = BigEndian32((uint32_t)path_length + 1);
		WriteAndSeek(&ptr, &tmp, sizeof(tmp));
		WriteAndSeek(&ptr, file->Path, path_length);
		free(file->Path);

		tmp = BigEndian32((uint32_t)file->OriginalSize);
		WriteAndSeek(&ptr, &tmp, sizeof(tmp));

		tmp = BigEndian32((uint32_t)file->Size);
		WriteAndSeek(&ptr, &tmp, sizeof(tmp));

		tmp = BigEndian32((uint32_t)file->Offset);
		WriteAndSeek(&ptr, &tmp, sizeof(tmp));
	}

	for (size_t i = 0; i < num; ++i)
	{
		CompressedFile *file = &files[i];
		WriteAndSeek(&ptr, file->Data, file->Size);
		free(file->Data);
	}

	free(files);

	bool ok = false;

	FILE *handle = FileOpen(dst, true);
	if (!handle)
	{
		printf("FileOpen() failed!\n");
		goto FINAL;
	}

	printf("\nWriting to \"%s\"...\n", dst);

	if (!FileWrite(handle, buffer, buffer_size))
	{
		printf("FileWrite() failed!\n");
		goto FINAL;
	}

	ok = true;
FINAL:
	FileClose(handle);
	free(buffer);
	return ok;
}

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

	if (!BuildHamcore(dst, src))
	{
		return 1;
	}

	printf("\nDone!\n");
	return 0;
}
