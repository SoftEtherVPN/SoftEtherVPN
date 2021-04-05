// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Database.h
// Header of Database.c

#ifndef	DATABASE_H
#define	DATABASE_H

#include "Mayaqua/MayaType.h"

wchar_t *LiGetLicenseStatusStr(UINT i);
bool LiIsLicenseKey(char *str);
bool LiStrToKeyBit(UCHAR *keybit, char *keystr);


#endif	// DATABASE_H


