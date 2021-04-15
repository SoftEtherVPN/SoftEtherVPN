// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLanUnix.h
// Header of VLanUnix.c

#ifdef OS_UNIX

#ifndef	VLANUNIX_H
#define	VLANUNIX_H

#include "CedarType.h"

#include "VLan.h"

#include "Mayaqua/MayaType.h"

// Constant
#define	TAP_READ_BUF_SIZE			1600

#ifndef	NO_VLAN

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halt flag
	char *InstanceName;			// Instance name
	int fd;						// File
};

// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
VLAN *NewTap(char *name, char *mac_address, bool create_up);
void FreeVLan(VLAN *v);
void FreeTap(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

#else	// NO_VLAN

#define	VLanGetPacketAdapter	NullGetPacketAdapter

#endif	// NO_VLAN

struct UNIX_VLAN_LIST
{
	char Name[MAX_SIZE];		// Device name
	int fd;						// fd
};

int UnixCreateTapDevice(char *name, UCHAR *mac_address, bool create_up);
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address, bool create_up);
void UnixCloseTapDevice(int fd);
void UnixVLanInit();
void UnixVLanFree();
bool UnixVLanCreate(char *name, UCHAR *mac_address, bool create_up);
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address, bool create_up);
TOKEN_LIST *UnixVLanEnum();
void UnixVLanDelete(char *name);
bool UnixVLanSetState(char* name, bool state_up);
int UnixVLanGet(char *name);
int UnixCompareVLan(void *p1, void *p2);

#endif // VLANUNIX_H

#endif // OS_UNIX
