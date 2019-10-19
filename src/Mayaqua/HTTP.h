#ifndef HTTP_H
#define HTTP_H

// MIME type
struct HTTP_MIME_TYPE
{
	char *Extension;
	char *MimeType;
};

char *GetMimeTypeFromFileName(char *filename);

#endif
