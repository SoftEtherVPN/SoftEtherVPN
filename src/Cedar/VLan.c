// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLan.c
// Virtual LAN card adapter manipulation library

#include <GlobalConst.h>

#define	VLAN_C

#ifdef	WIN32
#define	OS_WIN32
#endif

#ifdef	OS_WIN32

// For Win32
#include "VLanWin32.c"

#else

// For UNIX
#include "VLanUnix.c"

#endif	// OS_WIN32


