// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// WebUI.h
// Header of WebUI.c

#ifndef WEBUI_H
#define WEBUI_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

#define WU_PASSWORD_NOCHANGE	"********"
#define WU_CONTEXT_EXPIRE 600000

// Prototype declaration

typedef struct WEBUI
{
	CEDAR *Cedar;
	LIST *PageList;
	LIST *Contexts;
} WEBUI;

// WebUI context
typedef struct WU_CONTEXT
{
	ADMIN *Admin;
	UINT64 ExpireDate;
} WU_CONTEXT;

typedef struct WU_WEBPAGE
{
	char *data;
	UINT size;
	HTTP_HEADER *header;
} WU_WEBPAGE;

// Prototype declaration
bool WuFreeWebUI(WEBUI *wu);
WEBUI *WuNewWebUI(CEDAR *cedar);
WU_WEBPAGE *WuGetPage(char *target, WEBUI *wu);
void WuFreeWebPage(WU_WEBPAGE *page);

#endif
