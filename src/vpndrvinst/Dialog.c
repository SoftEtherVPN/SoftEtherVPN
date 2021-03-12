#include "Dialog.h"

#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

int ShowMessage(const char *title, const char *message, const unsigned int type, const va_list args)
{
	char buf[MAX_MESSAGE_SIZE];
	vsnprintf(buf, sizeof(buf), message, args);
	return MessageBox(NULL, buf, title, type);
}

int ShowInformation(const char *title, const char *message, ...)
{
	va_list args;
	va_start(args, message);
	const int ret = ShowMessage(title, message, MB_OK | MB_ICONINFORMATION, args);
	va_end(args);

	return ret;
}

int ShowWarning(const char *title, const char *message, ...)
{
	va_list args;
	va_start(args, message);
	const int ret = ShowMessage(title, message, MB_OK | MB_ICONWARNING, args);
	va_end(args);

	return ret;
}
