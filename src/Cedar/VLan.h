// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLan.h
// Header of VLan.c

#ifndef	VLAN_H
#define	VLAN_H

// Parameters related to VLAN
struct VLAN_PARAM
{
	UCHAR MacAddress[6];
	UCHAR Padding[2];
};

#ifdef	OS_WIN32

// For Win32
#include <Cedar/VLanWin32.h>

#else	// OS_WIN32

// For UNIX
#include <Cedar/VLanUnix.h>

#endif	// OS_WIN32

#endif	// VLAN_H


