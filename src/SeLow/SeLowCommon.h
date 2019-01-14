// SoftEther VPN Source Code - Developer Edition Master Branch
// SeLow - SoftEther Lightweight Network Protocol


// SeLowCommon.h
// Common Header for Kernel Mode / User Mode

//// Version number
// Change this number every time functions are added or modified on the driver.
// As long as this number does not change, installation of SeLow during the update
// installation of the VPN Server / VPN Client / VPN Bridge is skipped.
#define	SL_VER						48

// Constants
#define	SL_MAX_PACKET_SIZE			1600
#define	SL_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	SL_MIN_PACKET_SIZE			14
#define	SL_PACKET_HEADER_SIZE		14
#define	SL_MAX_FRAME_SIZE			(SL_MAX_PACKET_SIZE - SL_MIN_PACKET_SIZE)

#define	SL_PROTOCOL_NAME			"SeLow"
#define	SL_EVENT_NAME_SIZE			128

#define	SL_ENUM_COMPLETE_GIVEUP_TICK	(15 * 1000)

// IOCTL
#define	SL_IOCTL_GET_EVENT_NAME		CTL_CODE(0x8000, 1, METHOD_NEITHER, FILE_ANY_ACCESS)

// IOCTL data structure
typedef struct SL_IOCTL_EVENT_NAME
{
	char EventNameWin32[SL_EVENT_NAME_SIZE];		// Event name
} SL_IOCTL_EVENT_NAME;

// Device ID
#define	SL_BASIC_DEVICE_NAME			"\\Device\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_BASIC_DEVICE"
#define	SL_BASIC_DEVICE_FILENAME_WIN32	"\\\\.\\SELOW_BASIC_DEVICE"
#define	SL_ADAPTER_ID_PREFIX			"SELOW_A_"
#define	SL_ADAPTER_ID_PREFIX_W			L"SELOW_A_"
#define	SL_ADAPTER_DEVICE_NAME			"\\Device\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_NAME_SYMBOLIC	"\\DosDevices\\Global\\SELOW_A_{00000000-0000-0000-0000-000000000000}"
#define	SL_ADAPTER_DEVICE_FILENAME_WIN32	"\\\\.\\%s"

// Event name
#define	SL_EVENT_NAME					"\\BaseNamedObjects\\SELOW_EVENT_%u_%u"
#define	SL_EVENT_NAME_WIN32				"Global\\SELOW_EVENT_%u_%u"

// Registry key
#define	SL_REG_KEY_NAME					"SYSTEM\\CurrentControlSet\\services\\SeLow"
#define	SL_REG_VER_VALUE				"SlVersion"
#define	SL_REG_VER_VALUE_WIN10			"SlVersion_Win10"

// Adapter data
#define	SL_ADAPTER_ID_LEN				64
typedef struct SL_ADAPTER_INFO
{
	wchar_t AdapterId[SL_ADAPTER_ID_LEN];	// Adapter ID
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding1[2];
	UINT MtuSize;						// MTU size
	char FriendlyName[256];				// Display name
	UINT SupportsVLanHw;				// Supports VLAN by HW
	UCHAR Reserved[256 - sizeof(UINT)];	// Reserved area
} SL_ADAPTER_INFO;

#define	SL_MAX_ADAPTER_INFO_LIST_ENTRY	256
#define	SL_SIGNATURE					0xDEADBEEF

typedef struct SL_ADAPTER_INFO_LIST
{
	UINT Signature;													// Signature
	UINT SeLowVersion;												// Version of SeLow
	UINT EnumCompleted;												// Enumeration completion flag
	UINT NumAdapters;												// The total number of adapter
	SL_ADAPTER_INFO Adapters[SL_MAX_ADAPTER_INFO_LIST_ENTRY];		// Array of adapter
} SL_ADAPTER_INFO_LIST;


// Packet data exchange related
#define	SL_MAX_PACKET_EXCHANGE		256			// Number of packets that can be exchanged at a time
#define	SL_MAX_PACKET_QUEUED		4096		// Maximum number of packets that can be queued
#define	SL_EX_SIZEOF_NUM_PACKET	4			// Packet count data (UINT)
#define	SL_EX_SIZEOF_LENGTH_PACKET	4			// Length data of the packet data (UINT)
#define	SL_EX_SIZEOF_LEFT_FLAG		4			// Flag to indicate that the packet is left
#define	SL_EX_SIZEOF_ONE_PACKET	1600		// Data area occupied by a packet data
#define	SL_EXCHANGE_BUFFER_SIZE	(SL_EX_SIZEOF_NUM_PACKET + SL_EX_SIZEOF_LEFT_FLAG +	\
	(SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET) * (SL_MAX_PACKET_EXCHANGE + 1))
#define	SL_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	SL_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + SL_EX_SIZEOF_NUM_PACKET + \
	SL_EX_SIZEOF_LENGTH_PACKET +	\
	(i * (SL_EX_SIZEOF_LENGTH_PACKET + SL_EX_SIZEOF_ONE_PACKET)))))
#define	SL_LEFT_FLAG(buf)			SL_SIZE_OF_PACKET(buf, SL_MAX_PACKET_EXCHANGE)


