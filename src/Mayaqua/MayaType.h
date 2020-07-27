// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// MayaType.h
// Mayaqua Kernel type declaration header file

#ifndef	MAYATYPE_H
#define	MAYATYPE_H

// Check whether the windows.h header is included
#ifndef	WINDOWS_H
#ifdef	_WINDOWS_
#define	WINDOWS_H
#endif	// _WINDOWS_
#endif	// WINDOWS_H


#if	!defined(ENCRYPT_C)
// Structure which is used by OpenSSL
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct X509_req_st X509_REQ;
typedef struct PKCS12 PKCS12;
typedef struct bignum_st BIGNUM;
typedef struct x509_crl_st X509_CRL;
#endif	// ENCRYPT_C

// 
// Constant
// 

// Standard buffer size
#define	STD_SIZE			512
#define	MAX_SIZE			512
#define	BUF_SIZE			512

// Support Windows OS list
#define	SUPPORTED_WINDOWS_LIST		"Windows 98 / 98 SE / ME / NT 4.0 SP6a / 2000 SP4 / XP SP2, SP3 / Vista SP1, SP2 / 7 SP1 / 8 / 8.1 / 10 / Server 2003 SP2 / Server 2008 SP1, SP2 / Hyper-V Server 2008 / Server 2008 R2 SP1 / Hyper-V Server 2008 R2 / Server 2012 / Hyper-V Server 2012 / Server 2012 R2 / Hyper-V Server 2012 R2 / Server 2016 / Server 2019"

// Infinite
#ifndef	WINDOWS_H
#define	INFINITE			(0xFFFFFFFF)
#endif


#define	SRC_NAME			__FILE__	// File name of the source code
#define	SRC_LINE			__LINE__	// Line number in the source code

// Maximum path size
#ifndef	WINDOWS_H
#define	MAX_PATH			260
#endif	// WINDOWS_H

// Types of seek
#ifndef	FILE_BEGIN
#define	FILE_BEGIN	SEEK_SET
#endif	// FILE_BEGIN
#ifndef	FILE_END
#define	FILE_END	SEEK_END
#endif	// FILE_END
#ifndef	FILE_CURRENT
#define	FILE_CURRENT	SEEK_CUR
#endif	// FILE_CURRENT

#ifndef	INVALID_SOCKET
#define	INVALID_SOCKET		(-1)
#endif	// INVALID_SOCKET

#ifndef	SOCKET_ERROR
#define	SOCKET_ERROR		(-1)
#endif	//SOCKET_ERROR

// Comparison function
typedef int (COMPARE)(void *p1, void *p2);


// 
// Macro


#ifdef	MAX
#undef	MAX
#endif	// MAX

#ifdef	MIN
#undef	MIN
#endif	// MIN

// Minimum value of a and b
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
// Maximum value of a and b
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))

// Convert an int value to bool
#define	INT_TO_BOOL(i)		(((i) == 0) ? false : true)
#define	MAKEBOOL(i)			INT_TO_BOOL(i)
#define	BOOL_TO_INT(i)		(((i) == false) ? 0 : 1)

// Invert the bool type value
#define	NEGATIVE_BOOL(i)	(((i) == false) ? true : false)

// Return 'a' less than max_value
#define	LESS(a, max_value)	((a) <= (max_value) ? (a) : (max_value))
// Return 'a' greater than min_value
#define	MORE(a, min_value)	((a) >= (min_value) ? (a) : (min_value))
// Examine whether the value a is between the b and c
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
// Examine whether the value a is outbound of b and c
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
// Adjust value 'a' to be between b and c
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
// Compare a and b
#define COMPARE_RET(a, b)	(((a) == (b)) ? 0 : (((a) > (b)) ? 1 : -1))
// Compare bool type values
#define	EQUAL_BOOL(a, b)	(((a) && (b)) || ((!(a)) && (!(b))))
// Get the absolute value
#define	GET_ABS(a)			((a) >= 0 ? (a) : -(a))

// Convert the pointer to UINT
#ifdef	CPU_64
#define	POINTER_TO_KEY(p)		HashPtrToUINT(p)
#else
#define	POINTER_TO_KEY(p)		(UINT)(p)
#endif

// Compare the pointer and UINT
#define	COMPARE_POINTER_AND_KEY(p, i)	(POINTER_TO_KEY(p) == (i))

// Convert the pointer to UINT64
#ifdef	CPU_64
#define	POINTER_TO_UINT64(p)	(UINT64)(p)
#else
#define	POINTER_TO_UINT64(p)	(UINT64)((UINT)(p))
#endif

// Convert a UINT64 to pointer
#ifdef	CPU_64
#define	UINT64_TO_POINTER(i)	(void *)(i)
#else
#define	UINT64_TO_POINTER(i)	(void *)((UINT)(i))
#endif

// Add the value
#define	UINT_ADD(i, j)		((i == INFINITE || i == 0x7fffffff) ? (i) : (i += j))

// Reading data that is not dependent on the boundary or the endian
#define	READ_USHORT(buf)		(USHORT)((((USHORT)((UCHAR *)(buf))[0]) << 8) | (((USHORT)((UCHAR *)(buf))[1])))
#define	READ_UINT(buf)			(UINT)((((UINT)((UCHAR *)(buf))[0]) << 24) | (((UINT)((UCHAR *)(buf))[1]) << 16) | (((UINT)((UCHAR *)(buf))[2]) << 8) | (((UINT)((UCHAR *)(buf))[3])))
#define	READ_UINT64(buf)		(UINT64)((((UINT64)((UCHAR *)(buf))[0]) << 56) | (((UINT64)((UCHAR *)(buf))[1]) << 48) | (((UINT64)((UCHAR *)(buf))[2]) << 40) | (((UINT64)((UCHAR *)(buf))[3]) << 32) | (((UINT64)((UCHAR *)(buf))[4]) << 24) | (((UINT64)((UCHAR *)(buf))[5]) << 16) | (((UINT64)((UCHAR *)(buf))[6]) << 8) | (((UINT64)((UCHAR *)(buf))[7])))

// Writing data that is not dependent on the boundary or endian
#define	WRITE_USHORT(buf, i)	(((UCHAR *)(buf))[0]) = ((((USHORT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[1]) = ((((USHORT)(i))) & 0xFF)
#define	WRITE_UINT(buf, i)		(((UCHAR *)(buf))[0]) = ((((UINT)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT)(i))) & 0xFF)
#define	WRITE_UINT64(buf, i)	(((UCHAR *)(buf))[0]) = ((((UINT64)(i)) >> 56) & 0xFF); (((UCHAR *)(buf))[1]) = ((((UINT64)(i)) >> 48) & 0xFF); (((UCHAR *)(buf))[2]) = ((((UINT64)(i)) >> 40) & 0xFF); (((UCHAR *)(buf))[3]) = ((((UINT64)(i)) >> 32) & 0xFF); (((UCHAR *)(buf))[4]) = ((((UINT64)(i)) >> 24) & 0xFF); (((UCHAR *)(buf))[5]) = ((((UINT64)(i)) >> 16) & 0xFF); (((UCHAR *)(buf))[6]) = ((((UINT64)(i)) >> 8) & 0xFF); (((UCHAR *)(buf))[7]) = ((((UINT64)(i))) & 0xFF)



// 
// Type declaration
// 

// PID type
#ifdef OS_UNIX
typedef int PID;
#endif // OS_UNIX
#ifdef OS_WIN32
typedef unsigned long PID;
#endif // WINDOWS_H

// bool type
#ifndef	WINDOWS_H
typedef	unsigned int		BOOL;
#define	TRUE				1
#define	FALSE				0
#endif	// WINDOWS_H

// bool type
#ifndef	WIN32COM_CPP
typedef	unsigned int		bool;
#define	true				1
#define	false				0
#endif	// WIN32COM_CPP

// 32bit integer type
#ifndef	WINDOWS_H
typedef	unsigned int		UINT;
typedef	unsigned int		UINT32;
typedef	unsigned int		DWORD;
typedef	signed int			INT;
typedef	signed int			INT32;

typedef	int					UINT_PTR;
typedef	long				LONG_PTR;

#endif

// 16bit integer type
typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;

// 8bit integer type
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;

#ifndef	WIN32COM_CPP
typedef signed char			CHAR;
#endif	// WIN32COM_CPP


// 64-bit integer type
typedef	unsigned long long	UINT64;
typedef signed long long	INT64;

typedef signed long long	time_64t;

#ifdef	OS_UNIX
// Avoiding compile error
#define	__cdecl
#define	__declspec(x)
// socket type
typedef	int SOCKET;
#else	// OS_UNIX
#ifndef	_WINSOCK2API_
typedef UINT_PTR SOCKET;
#endif	// _WINSOCK2API_
#endif	// OS_UNIX

// OS type
#define	OSTYPE_WINDOWS_95						1100	// Windows 95
#define	OSTYPE_WINDOWS_98						1200	// Windows 98
#define	OSTYPE_WINDOWS_ME						1300	// Windows Me
#define	OSTYPE_WINDOWS_UNKNOWN					1400	// Windows (unknown)
#define	OSTYPE_WINDOWS_NT_4_WORKSTATION			2100	// Windows NT 4.0 Workstation
#define	OSTYPE_WINDOWS_NT_4_SERVER				2110	// Windows NT 4.0 Server
#define	OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE	2111	// Windows NT 4.0 Server, Enterprise Edition
#define	OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER		2112	// Windows NT 4.0 Terminal Server
#define	OSTYPE_WINDOWS_NT_4_BACKOFFICE			2113	// BackOffice Server 4.5
#define	OSTYPE_WINDOWS_NT_4_SMS					2114	// Small Business Server 4.5
#define	OSTYPE_WINDOWS_2000_PROFESSIONAL		2200	// Windows 2000 Professional
#define	OSTYPE_WINDOWS_2000_SERVER				2211	// Windows 2000 Server
#define	OSTYPE_WINDOWS_2000_ADVANCED_SERVER		2212	// Windows 2000 Advanced Server
#define	OSTYPE_WINDOWS_2000_DATACENTER_SERVER	2213	// Windows 2000 Datacenter Server
#define	OSTYPE_WINDOWS_2000_BACKOFFICE			2214	// BackOffice Server 2000
#define	OSTYPE_WINDOWS_2000_SBS					2215	// Small Business Server 2000
#define	OSTYPE_WINDOWS_XP_HOME					2300	// Windows XP Home Edition
#define	OSTYPE_WINDOWS_XP_PROFESSIONAL			2301	// Windows XP Professional
#define	OSTYPE_WINDOWS_2003_WEB					2410	// Windows Server 2003 Web Edition
#define	OSTYPE_WINDOWS_2003_STANDARD			2411	// Windows Server 2003 Standard Edition
#define	OSTYPE_WINDOWS_2003_ENTERPRISE			2412	// Windows Server 2003 Enterprise Edition
#define	OSTYPE_WINDOWS_2003_DATACENTER			2413	// Windows Server 2003 DataCenter Edition
#define	OSTYPE_WINDOWS_2003_BACKOFFICE			2414	// BackOffice Server 2003
#define	OSTYPE_WINDOWS_2003_SBS					2415	// Small Business Server 2003
#define	OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL	2500	// Windows Vista
#define	OSTYPE_WINDOWS_LONGHORN_SERVER			2510	// Windows Server 2008
#define	OSTYPE_WINDOWS_7						2600	// Windows 7
#define	OSTYPE_WINDOWS_SERVER_2008_R2			2610	// Windows Server 2008 R2
#define	OSTYPE_WINDOWS_8						2700	// Windows 8
#define	OSTYPE_WINDOWS_SERVER_8					2710	// Windows Server 2012
#define	OSTYPE_WINDOWS_81						2701	// Windows 8.1
#define	OSTYPE_WINDOWS_SERVER_81				2711	// Windows Server 2012 R2
#define	OSTYPE_WINDOWS_10						2702	// Windows 10
#define	OSTYPE_WINDOWS_SERVER_10				2712	// Windows Server 10
#define	OSTYPE_WINDOWS_11						2800	// Windows 11 or later
#define	OSTYPE_WINDOWS_SERVER_11				2810	// Windows Server 11 or later
#define	OSTYPE_UNIX_UNKNOWN						3000	// Unknown UNIX
#define	OSTYPE_LINUX							3100	// Linux
#define	OSTYPE_SOLARIS							3200	// Solaris
#define	OSTYPE_CYGWIN							3300	// Cygwin
#define	OSTYPE_BSD								3400	// BSD
#define	OSTYPE_MACOS_X							3500	// MacOS X


// OS discrimination macro
#define	GET_KETA(t, i)			(((t) % (i * 10)) / i)
#define	OS_IS_WINDOWS_9X(t)		(GET_KETA(t, 1000) == 1)
#define	OS_IS_WINDOWS_NT(t)		(GET_KETA(t, 1000) == 2)
#define	OS_IS_WINDOWS(t)		(OS_IS_WINDOWS_9X(t) || OS_IS_WINDOWS_NT(t))
#define	OS_IS_SERVER(t)			(OS_IS_WINDOWS_NT(t) && GET_KETA(t, 10))
#define	OS_IS_WORKSTATION(t)	((OS_IS_WINDOWS_NT(t) && (!(GET_KETA(t, 10)))) || OS_IS_WINDOWS_9X(t))
#define	OS_IS_UNIX(t)			(GET_KETA(t, 1000) == 3)


// OS information
typedef struct OS_INFO
{
	UINT OsType;								// OS type
	UINT OsServicePack;							// Service pack number
	char *OsSystemName;							// OS system name
	char *OsProductName;						// OS product name
	char *OsVendorName;							// OS vendor name
	char *OsVersion;							// OS version
	char *KernelName;							// Kernel name
	char *KernelVersion;						// Kernel version
} OS_INFO;

// Time type
#ifndef	WINDOWS_H
typedef struct SYSTEMTIME
{
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
} SYSTEMTIME;
#endif	// WINDOWS_H


// Object.h
typedef struct LOCK LOCK;
typedef struct COUNTER COUNTER;
typedef struct REF REF;
typedef struct EVENT EVENT;
typedef struct DEADCHECK DEADCHECK;

// Tracking.h
typedef struct CALLSTACK_DATA CALLSTACK_DATA;
typedef struct TRACKING_OBJECT TRACKING_OBJECT;
typedef struct MEMORY_STATUS MEMORY_STATUS;
typedef struct TRACKING_LIST TRACKING_LIST;

// FileIO.h
typedef struct IO IO;

// Memory.h
typedef struct MEMTAG MEMTAG;
typedef struct BUF BUF;
typedef struct FIFO FIFO;
typedef struct LIST LIST;
typedef struct QUEUE QUEUE;
typedef struct SK SK;
typedef struct CANDIDATE CANDIDATE;
typedef struct STRMAP_ENTRY STRMAP_ENTRY;
typedef struct SHARED_BUFFER SHARED_BUFFER;
typedef struct HASH_LIST HASH_LIST;
typedef struct HASH_ENTRY HASH_ENTRY;
typedef struct PRAND PRAND;

// Str.h
typedef struct TOKEN_LIST TOKEN_LIST;
typedef struct INI_ENTRY INI_ENTRY;
typedef struct JSON_OBJECT JSON_OBJECT;
typedef struct JSON_ARRAY  JSON_ARRAY;
typedef struct JSON_VALUE  JSON_VALUE;

// Internat.h
typedef struct UNI_TOKEN_LIST UNI_TOKEN_LIST;

// Encrypt.h
typedef struct CRYPT CRYPT;
typedef struct NAME NAME;
typedef struct X_SERIAL X_SERIAL;
typedef struct X X;
typedef struct K K;
typedef struct P12 P12;
typedef struct X_CRL X_CRL;
typedef struct DES_KEY_VALUE DES_KEY_VALUE;
typedef struct DES_KEY DES_KEY;
typedef struct DH_CTX DH_CTX;
typedef struct AES_KEY_VALUE AES_KEY_VALUE;
typedef struct CIPHER CIPHER;
typedef struct MD MD;

// Secure.h
typedef struct SECURE_DEVICE SECURE_DEVICE;
typedef struct SEC_INFO SEC_INFO;
typedef struct SECURE SECURE;
typedef struct SEC_OBJ SEC_OBJ;

// Kernel.h
typedef struct MEMINFO MEMINFO;
typedef struct LOCALE LOCALE;
typedef struct THREAD THREAD;
typedef struct THREAD_POOL_DATA THREAD_POOL_DATA;
typedef struct INSTANCE INSTANCE;

// Pack.h
typedef struct VALUE VALUE;
typedef struct ELEMENT ELEMENT;
typedef struct PACK PACK;
typedef struct JSONPACKHINT JSONPACKHINT;
typedef struct JSONPACKHINT_ITEM JSONPACKHINT_ITEM;

// Cfg.h
typedef struct FOLDER FOLDER;
typedef struct ITEM ITEM;
typedef struct CFG_RW CFG_RW;
typedef struct CFG_ENUM_PARAM CFG_ENUM_PARAM;

// Table.h
typedef struct TABLE TABLE;
typedef struct LANGLIST LANGLIST;

// Network.h
typedef struct IP IP;
typedef struct DNSCACHE DNSCACHE;
typedef struct SOCK_EVENT SOCK_EVENT;
typedef struct SOCK SOCK;
typedef struct SOCKSET SOCKSET;
typedef struct CANCEL CANCEL;
typedef struct ROUTE_ENTRY ROUTE_ENTRY;
typedef struct ROUTE_TABLE ROUTE_TABLE;
typedef struct IP_CLIENT IP_CLIENT;
typedef struct ROUTE_CHANGE ROUTE_CHANGE;
typedef struct ROUTE_CHANGE_DATA ROUTE_CHANGE_DATA;
typedef struct GETIP_THREAD_PARAM GETIP_THREAD_PARAM;
typedef struct WIN32_RELEASEADDRESS_THREAD_PARAM WIN32_RELEASEADDRESS_THREAD_PARAM;
typedef struct IPV6_ADDR IPV6_ADDR;
typedef struct TUBE TUBE;
typedef struct TUBEDATA TUBEDATA;
typedef struct PSEUDO PSEUDO;
typedef struct TUBEPAIR_DATA TUBEPAIR_DATA;
typedef struct UDPLISTENER UDPLISTENER;
typedef struct UDPLISTENER_SOCK UDPLISTENER_SOCK;
typedef struct UDPPACKET UDPPACKET;
typedef struct TCP_RAW_DATA TCP_RAW_DATA;
typedef struct INTERRUPT_MANAGER INTERRUPT_MANAGER;
typedef struct TUBE_FLUSH_LIST TUBE_FLUSH_LIST;
typedef struct ICMP_RESULT ICMP_RESULT;
typedef struct SSL_PIPE SSL_PIPE;
typedef struct SSL_BIO SSL_BIO;
typedef struct RUDP_STACK RUDP_STACK;
typedef struct RUDP_SOURCE_IP RUDP_SOURCE_IP;
typedef struct RUDP_SESSION RUDP_SESSION;
typedef struct RUDP_SEGMENT RUDP_SEGMENT;
typedef struct CONNECT_TCP_RUDP_PARAM CONNECT_TCP_RUDP_PARAM;
typedef struct TCP_PAIR_HEADER TCP_PAIR_HEADER;
typedef struct NIC_ENTRY NIC_ENTRY;
typedef struct HTTP_VALUE HTTP_VALUE;
typedef struct HTTP_HEADER HTTP_HEADER;
typedef struct DNSPROXY_CLIENT DNSPROXY_CLIENT;
typedef struct DNSPROXY_CACHE DNSPROXY_CACHE;
typedef struct QUERYIPTHREAD QUERYIPTHREAD;
typedef struct IPBLOCK IPBLOCK;
typedef struct SAFE_REQUEST SAFE_REQUEST;
typedef struct SAFE_LIST SAFE_LIST;
typedef struct SAFE_QUOTA SAFE_QUOTA;
typedef struct SAFE_QUOTA2 SAFE_QUOTA2;
typedef struct SAFE_BLOCK SAFE_BLOCK;
typedef struct SAFE_REQUEST_LOG SAFE_REQUEST_LOG;
typedef struct DYN_VALUE DYN_VALUE;
typedef struct RELAY_PARAMETER RELAY_PARAMETER;
typedef struct SSL_ACCEPT_SETTINGS SSL_ACCEPT_SETTINGS;

// Tick64.h
typedef struct ADJUST_TIME ADJUST_TIME;
typedef struct TICK64 TICK64;

// FileIO.h
typedef struct DIRENT DIRENT;
typedef struct DIRLIST DIRLIST;
typedef struct ZIP_DATA_HEADER ZIP_DATA_HEADER;
typedef struct ZIP_DATA_FOOTER ZIP_DATA_FOOTER;
typedef struct ZIP_DIR_HEADER ZIP_DIR_HEADER;
typedef struct ZIP_END_HEADER ZIP_END_HEADER;
typedef struct ZIP_FILE ZIP_FILE;
typedef struct ZIP_PACKER ZIP_PACKER;
typedef struct ENUM_DIR_WITH_SUB_DATA ENUM_DIR_WITH_SUB_DATA;

// TcpIp.h
typedef struct MAC_HEADER MAC_HEADER;
typedef struct ARPV4_HEADER ARPV4_HEADER;
typedef struct IPV4_HEADER IPV4_HEADER;
typedef struct TAGVLAN_HEADER TAGVLAN_HEADER;
typedef struct UDP_HEADER UDP_HEADER;
typedef struct UDPV4_PSEUDO_HEADER UDPV4_PSEUDO_HEADER;
typedef struct IPV4_PSEUDO_HEADER IPV4_PSEUDO_HEADER;
typedef struct TCP_HEADER TCP_HEADER;
typedef struct ICMP_HEADER ICMP_HEADER;
typedef struct ICMP_ECHO ICMP_ECHO;
typedef struct DHCPV4_HEADER DHCPV4_HEADER;
typedef struct DNSV4_HEADER DNSV4_HEADER;
typedef struct BPDU_HEADER BPDU_HEADER;
typedef struct LLC_HEADER LLC_HEADER;
typedef struct PKT PKT;
typedef struct IPV6_HEADER_PACKET_INFO IPV6_HEADER_PACKET_INFO;
typedef struct IPV6_HEADER IPV6_HEADER;
typedef struct IPV6_OPTION_HEADER IPV6_OPTION_HEADER;
typedef struct IPV6_FRAGMENT_HEADER IPV6_FRAGMENT_HEADER;
typedef struct IPV6_PSEUDO_HEADER IPV6_PSEUDO_HEADER;
typedef struct ICMPV6_ROUTER_SOLICIATION_HEADER ICMPV6_ROUTER_SOLICIATION_HEADER;
typedef struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER ICMPV6_ROUTER_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER ICMPV6_NEIGHBOR_SOLICIATION_HEADER;
typedef struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER;
typedef struct ICMPV6_OPTION_LIST ICMPV6_OPTION_LIST;
typedef struct ICMPV6_OPTION ICMPV6_OPTION;
typedef struct ICMPV6_OPTION_LINK_LAYER ICMPV6_OPTION_LINK_LAYER;
typedef struct ICMPV6_OPTION_PREFIX ICMPV6_OPTION_PREFIX;
typedef struct ICMPV6_OPTION_MTU ICMPV6_OPTION_MTU;
typedef struct IPV6_HEADER_INFO IPV6_HEADER_INFO;
typedef struct ICMPV6_HEADER_INFO ICMPV6_HEADER_INFO;
typedef struct DHCPV4_DATA DHCPV4_DATA;
typedef struct DHCP_OPTION DHCP_OPTION;
typedef struct DHCP_OPTION_LIST DHCP_OPTION_LIST;
typedef struct DHCP_CLASSLESS_ROUTE DHCP_CLASSLESS_ROUTE;
typedef struct DHCP_CLASSLESS_ROUTE_TABLE DHCP_CLASSLESS_ROUTE_TABLE;
typedef struct HTTPLOG HTTPLOG;
typedef struct DHCP_MODIFY_OPTION DHCP_MODIFY_OPTION;
typedef struct NBTDG_HEADER NBTDG_HEADER;
typedef struct IKE_HEADER IKE_HEADER;

// HTTP.h
typedef struct HTTP_MIME_TYPE HTTP_MIME_TYPE;

// Proxy.h
typedef struct PROXY_PARAM_IN PROXY_PARAM_IN;
typedef struct PROXY_PARAM_OUT PROXY_PARAM_OUT;

#endif	// MAYATYPE_H
