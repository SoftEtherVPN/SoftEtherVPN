// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Cedar.h
// Header of Cedar.c

#ifndef	CEDAR_H
#define	CEDAR_H


//////////////////////////////////////////////////////////////////////
// 
// Products related constants
// 
//////////////////////////////////////////////////////////////////////

// Replace the function name
#ifdef	VPN_SPEED

#define	DecryptSecurePacket	__dsp
#define	CreateSecurePacket	__csp
#define	GetSecureRandomSize	__gsrs

#endif	// VPN_SPEED

#define	bool	UINT
#define	BOOL	UINT


// Version number
#ifndef	CEDAR_VERSION_MAJOR
#define	CEDAR_VERSION_MAJOR		0
#endif	// CEDAR_VERSION_MAJOR

#ifndef	CEDAR_VERSION_MINOR
#define	CEDAR_VERSION_MINOR		0
#endif	// CEDAR_VER_MINOR

// Build number
#ifndef	CEDAR_VERSION_BUILD
#define	CEDAR_VERSION_BUILD		0
#endif	// CEDAR_VERSION_BUILD

// Beta number
//#define	BETA_NUMBER					3

// RC or not
#define	RELEASE_CANDIDATE

// Specify the name of the person in charge building
#ifndef	BUILDER_NAME
#define	BUILDER_NAME			"Unknown"
#endif	// BUILDER_NAME

// Specify the location to build
#ifndef	BUILD_PLACE
#define	BUILD_PLACE				"Unknown"
#endif	// BUILD_PLACE

// Specifies the build date
#ifndef	BUILD_DATE_Y
#define	BUILD_DATE_Y			1970
#endif	// BUILD_DATE_Y

#ifndef	BUILD_DATE_M
#define	BUILD_DATE_M			1
#endif	// BUILD_DATE_M

#ifndef	BUILD_DATE_D
#define	BUILD_DATE_D			1
#endif	// BUILD_DATE_D

#ifndef	BUILD_DATE_HO
#define	BUILD_DATE_HO			0
#endif	// BUILD_DATE_HO

#ifndef	BUILD_DATE_MI
#define	BUILD_DATE_MI			0
#endif	// BUILD_DATE_MI

#ifndef	BUILD_DATE_SE
#define	BUILD_DATE_SE			0
#endif	// BUILD_DATE_SE

// Tolerable time difference
#define	ALLOW_TIMESTAMP_DIFF		(UINT64)(3 * 24 * 60 * 60 * 1000)


// Configuration of communication related control switch
#define	USE_DOS_ATTACK_DETECTION		// Enable the DOS attack detection
//#define	USE_SECURE_PACKET				// Enable the scrambled packet

// Designate the IDS detection signatures
#define	CEDAR_SIGNATURE_STR			"SE-VPN4-PROTOCOL"

// Default RSA certificate name of the smart card
#define	SECURE_DEFAULT_CERT_NAME	"VPN_RSA_CERT"

// Default RSA private key name of the smart card
#define	SECURE_DEFAULT_KEY_NAME		"VPN_RSA_KEY"

// Hidden password string of 8 characters
#define	HIDDEN_PASSWORD				"********"

// Default separator character for the hub name in the username
#define	DEFAULT_USERNAME_HUB_SEPARATOR	'@'


//////////////////////////////////////////////////////////////////////
// 
// Definition of the maximum length of various string
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_ACCOUNT_NAME_LEN		255		// Maximum account name length
#define	MAX_USERNAME_LEN			255		// User name maximum length
#define	MAX_PASSWORD_LEN			255		// Password name maximum length
#define	MAX_SERVER_STR_LEN			255		// Maximum length of server string
#define	MAX_CLIENT_STR_LEN			255		// Maximum length of client string
#define	MAX_HUBNAME_LEN				255		// Maximum length of HUB name
#define	MAX_SESSION_NAME_LEN		255		// Session name maximum length
#define	MAX_CONNECTION_NAME_LEN		255		// Maximum length of connection name
#define	MAX_DEVICE_NAME_LEN			31		// Device name maximum length
#define	MAX_DEVICE_NAME_LEN_9X		4		// Maximum length of Virtual LAN card name in Win9x
#define	MAX_ACCESSLIST_NOTE_LEN		255		// Maximum length of the note of access list entry
#define	MAX_SECURE_DEVICE_FILE_LEN	255		// Secure device file name maximum length
#define	MAX_ADMIN_OPTION_NAME_LEN	63		// Management option name
#define	MAX_REDIRECT_URL_LEN		255		// URL length to redirect


//////////////////////////////////////////////////////////////////////
// 
// Server and session management related constants
// 
//////////////////////////////////////////////////////////////////////

#define	SERVER_MAX_SESSIONS			4096	// Maximum number of sessions that the server supports
#define SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION	100000	// Maximum number of sessions that the server supports (Carrier Edition)
#define	NAT_MAX_SESSIONS			4096	// Maximum number of sessions that are supported by NAT
#define	NAT_MAX_SESSIONS_KERNEL		65536	// Maximum number of sessions that are supported by NAT (In the case of kernel-mode NAT)
#define	MAX_HUBS					4096	// The maximum number of virtual HUB
#define MAX_HUBS_FOR_CARRIER_EDITION	100000	// The maximum number of virtual HUB (Carrier Edition)
#define	MAX_ACCESSLISTS				(4096 * 8)	// Maximum number of access list entries
#define	MAX_USERS					10000	// The maximum number of users
#define	MAX_GROUPS					10000	// Maximum number of groups
#define	MAX_MAC_TABLES				VPN_GP(GP_MAX_MAC_TABLES, 65536)	// Maximum number of MAC address table entries
#define	MAX_IP_TABLES				VPN_GP(GP_MAX_IP_TABLES, 65536)	// Maximum number of IP address table entries
#define	MAX_HUB_CERTS				4096	// Maximum number of Root CA that can be registered
#define	MAX_HUB_CRLS				4096	// Maximum number of CRL that can be registered
#define	MAX_HUB_ACS					4096	// Maximum number of AC that can be registered
#define	MAX_HUB_LINKS				VPN_GP(GP_MAX_HUB_LINKS, 1024)	// Maximum number of Cascade that can be registered
#define	MAX_HUB_ADMIN_OPTIONS		4096	// Maximum number of Virtual HUB management options that can be registered

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	MEM_FIFO_REALLOC_MEM_SIZE	VPN_GP(GP_MEM_FIFO_REALLOC_MEM_SIZE, (65536 * 10))
#define	QUEUE_BUDGET				VPN_GP(GP_QUEUE_BUDGET, 2048)
#define	FIFO_BUDGET					VPN_GP(GP_FIFO_BUDGET, 1600 * 1600 * 4)
#else	// USE_STRATEGY_LOW_MEMORY
#define	MEM_FIFO_REALLOC_MEM_SIZE	VPN_GP(GP_MEM_FIFO_REALLOC_MEM_SIZE, (65536))
#define	QUEUE_BUDGET				VPN_GP(GP_QUEUE_BUDGET, 1024)
#define	FIFO_BUDGET					VPN_GP(GP_FIFO_BUDGET, 1000000)
#endif	// USE_STRATEGY_LOW_MEMORY

#define	MAX_PACKET_SIZE				1600	// Maximum packet size
#define	UDP_BUF_SIZE				(32 * 1024) // Aim of the UDP packet size

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	MAX_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE, (1600 * 1600 * 1))	// Maximum transmit queue size
#define	MIN_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE, (1600 * 200 * 1))	// Minimum transmit queue size
#define	MAX_STORED_QUEUE_NUM		VPN_GP(GP_MAX_STORED_QUEUE_NUM, 1024)		// The number of queues that can be stored in each session
#define	MAX_BUFFERING_PACKET_SIZE	VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE, (1600 * 1600))	// Maximum packet size can be buffered
#else	// USE_STRATEGY_LOW_MEMORY
#define	MAX_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_SIZE, (1600 * 200 * 1))	// Maximum transmit queue size
#define	MIN_SEND_SOCKET_QUEUE_SIZE	VPN_GP(GP_MIN_SEND_SOCKET_QUEUE_SIZE, (1600 * 50 * 1))	// Minimum transmit queue size
#define	MAX_STORED_QUEUE_NUM		VPN_GP(GP_MAX_STORED_QUEUE_NUM, 384)		// The number of queues that can be stored in each session
#define	MAX_BUFFERING_PACKET_SIZE	VPN_GP(GP_MAX_BUFFERING_PACKET_SIZE, (1600 * 300 * 1))	// Maximum packet size can be buffered
#endif	// USE_STRATEGY_LOW_MEMORY

#define	MAX_SEND_SOCKET_QUEUE_NUM	VPN_GP(GP_MAX_SEND_SOCKET_QUEUE_NUM, 128)		// Maximum number of transmission queue items per processing
#define	MAX_TCP_CONNECTION			32		// The maximum number of TCP connections
#define	NUM_TCP_CONNECTION_FOR_UDP_RECOVERY	2	// Maximum number of connections when using UDP recovery
#define	SELECT_TIME					VPN_GP(GP_SELECT_TIME, 256)
#define	SELECT_TIME_FOR_NAT			VPN_GP(GP_SELECT_TIME_FOR_NAT, 30)
#define	SELECT_TIME_FOR_DELAYED_PKT	1		// If there is a delayed packet

#define	TIMEOUT_MIN					(5 * 1000)	// Minimum timeout in seconds
#define	TIMEOUT_MAX					(60 * 1000)	// Maximum timeout in seconds
#define	TIMEOUT_DEFAULT				(30 * 1000) // Default number of seconds to timeout
#define	CONNECTING_TIMEOUT			(15 * 1000)	// Timeout in seconds of being connected
#define	CONNECTING_POOLING_SPAN		(3 * 1000) // Polling interval of connected
#define	MIN_RETRY_INTERVAL			(5 * 1000)		// Minimum retry interval
#define	MAX_RETRY_INTERVAL			(300 * 1000)	// Maximum retry interval
#define	RETRY_INTERVAL_SPECIAL		(60 * 1000)		// Reconnection interval of a special case

#define	MAX_ADDITIONAL_CONNECTION_FAILED_COUNTER	16	// Allowable number that can be serially failed to additional connection
#define	ADDITIONAL_CONNECTION_COUNTER_RESET_INTERVAL	(30 * 60 * 1000)	// Reset period of additional connection failure counter

#define	MAC_MIN_LIMIT_COUNT			3		// Minimum number of MAC addresses
#define	IP_MIN_LIMIT_COUNT			4		// Number of IPv4 addresses minimum
#define	IP_MIN_LIMIT_COUNT_V6		5		// Number of IPv6 addresses minimum
#define	IP_LIMIT_WHEN_NO_ROUTING_V6	15		// Maximum number of IPv6 addresses when NoRouting policy is enabled

#define	MAC_TABLE_EXCLUSIVE_TIME	(13 * 1000)			// Period that can occupy the MAC address
#define	IP_TABLE_EXCLUSIVE_TIME		(13 * 1000)			// Period that can occupy the IP address
#define	MAC_TABLE_EXPIRE_TIME		VPN_GP(GP_MAC_TABLE_EXPIRE_TIME, (600 * 1000))			// MAC address table expiration time
#define	IP_TABLE_EXPIRE_TIME		VPN_GP(GP_IP_TABLE_EXPIRE_TIME, (60 * 1000))			// IP address table expiration time
#define	IP_TABLE_EXPIRE_TIME_DHCP	VPN_GP(GP_IP_TABLE_EXPIRE_TIME_DHCP, (5 * 60 * 1000))		// IP address table expiration time (In the case of DHCP)
#define	HUB_ARP_SEND_INTERVAL		VPN_GP(GP_HUB_ARP_SEND_INTERVAL, (5 * 1000))			// ARP packet transmission interval (alive check)

#define	LIMITER_SAMPLING_SPAN		1000	// Sampling interval of the traffic limiting device

#define	STORM_CHECK_SPAN			VPN_GP(GP_STORM_CHECK_SPAN, 500)		// Broadcast storm check interval
#define	STORM_DISCARD_VALUE_START	VPN_GP(GP_STORM_DISCARD_VALUE_START, 3)		// Broadcast packet discard value start value
#define	STORM_DISCARD_VALUE_END		VPN_GP(GP_STORM_DISCARD_VALUE_END, 1024)	// Broadcast packet discard value end value

#define	KEEP_INTERVAL_MIN			5		// Packet transmission interval minimum value
#define	KEEP_INTERVAL_DEFAULT		50		// Packet transmission interval default value
#define	KEEP_INTERVAL_MAX			600		// Packet transmission interval maximum value
#define KEEP_TCP_TIMEOUT			1000	// TCP time-out value

#define	TICKET_EXPIRES				(60 * 1000)	// Expiration date of ticket

#define	SEND_KILL_NUM_X				256			// Number of 'X' characters to send the Kill


#define	FARM_BASE_POINT				100000		// Reference value of the cluster score
#define	FARM_DEFAULT_WEIGHT			100			// Standard performance ratio

#define DH_PARAM_BITS_DEFAULT		2048		// Bits of Diffie-Hellman Parameters


#define	SE_UDP_SIGN			"SE2P"		// Not used (only old UDP mode)

// R-UDP service name
#define	VPN_RUDP_SVC_NAME		"SoftEther_VPN"

// Traffic information update interval
#define	INCREMENT_TRAFFIC_INTERVAL		(10 * 1000)

// State of the client session
#define	CLIENT_STATUS_CONNECTING	0		// Connecting
#define	CLIENT_STATUS_NEGOTIATION	1		// Negotiating
#define	CLIENT_STATUS_AUTH			2		// During user authentication
#define	CLIENT_STATUS_ESTABLISHED	3		// Connection complete
#define	CLIENT_STATUS_RETRY			4		// Wait to retry
#define	CLIENT_STATUS_IDLE			5		// Idle state

// Expiration date of the black list
#define	BLACK_LIST_EXPIRES			(30 * 10000)

// Number Blacklist entries
#define	MAX_BLACK_LIST				4096
#define	BLACK_LIST_CHECK_SPAN		1000

// Blocks to be transmitted at one during the file transfer
#define	FTP_BLOCK_SIZE				(640 * 1024)

// Syslog configuration
#define SYSLOG_NONE							0		// Do not use syslog
#define SYSLOG_SERVER_LOG					1		// Only server log
#define SYSLOG_SERVER_AND_HUB_SECURITY_LOG	2		// Server and Virtual HUB security log
#define SYSLOG_SERVER_AND_HUB_ALL_LOG		3		// Server, Virtual HUB security, and packet log

#define SYSLOG_PORT					514			// Syslog port number
#define SYSLOG_POLL_IP_INTERVAL		(UINT64)(3600 * 1000)	// Interval to examine the IP address
#define	SYSLOG_POLL_IP_INTERVAL_NG	(UINT64)(60 * 1000)	// Interval to examine the IP address (previous failure)

//////////////////////////////////////////////////////////////////////
// 
// Connection-related constant
// 
//////////////////////////////////////////////////////////////////////

// Internet connection maintenance function (KeepAlive)

#define	KEEP_RETRY_INTERVAL		(60 * 1000)			// Reconnection interval on connection failure
#define	KEEP_MIN_PACKET_SIZE	1					// Minimum packet size
#define	KEEP_MAX_PACKET_SIZE	128					// Maximum packet size
#define	KEEP_POLLING_INTERVAL	250					// KEEP polling interval

// Constants
#define	RECV_BUF_SIZE				65536			// Buffer size to be received at a time

// Type of proxy
#define	PROXY_DIRECT			0	// Direct TCP connection
#define	PROXY_HTTP				1	// Connection via HTTP proxy server
#define	PROXY_SOCKS				2	// Connection via SOCKS4 proxy server
#define	PROXY_SOCKS5			3	// Connection via SOCKS5 proxy server

// Direction of data flow
#define	TCP_BOTH				0	// Bi-directional
#define	TCP_SERVER_TO_CLIENT	1	// Only server -> client direction
#define	TCP_CLIENT_TO_SERVER	2	// Only client -> server direction

// Type of connection
#define	CONNECTION_TYPE_CLIENT			0	// Client
#define	CONNECTION_TYPE_INIT			1	// During initialization
#define	CONNECTION_TYPE_LOGIN			2	// Login connection
#define	CONNECTION_TYPE_ADDITIONAL		3	// Additional connection
#define	CONNECTION_TYPE_FARM_RPC		4	// RPC for server farm
#define	CONNECTION_TYPE_ADMIN_RPC		5	// RPC for Management
#define	CONNECTION_TYPE_ENUM_HUB		6	// HUB enumeration
#define	CONNECTION_TYPE_PASSWORD		7	// Password change
#define	CONNECTION_TYPE_OTHER			0xffffffff	// E.g. Third-party protocol

// Protocol
#define	CONNECTION_TCP					0	// TCP protocol
#define	CONNECTION_UDP					1	// UDP protocol
#define	CONNECTION_HUB_LAYER3			6	// Layer-3 switch session
#define	CONNECTION_HUB_BRIDGE			7	// Bridge session
#define	CONNECTION_HUB_SECURE_NAT		8	// Secure NAT session
#define	CONNECTION_HUB_LINK_SERVER		9	// HUB link session


// Status
#define	CONNECTION_STATUS_ACCEPTED		0	// The connection is accepted (client side)
#define	CONNECTION_STATUS_NEGOTIATION	1	// Negotiating
#define	CONNECTION_STATUS_USERAUTH		2	// During user authentication
#define	CONNECTION_STATUS_ESTABLISHED	3	// Connection has been established
#define	CONNECTION_STATUS_CONNECTING	0	// Connecting (client side)

// Magic number of KeepAlive packet
#define	KEEP_ALIVE_MAGIC				0xffffffff
#define	MAX_KEEPALIVE_SIZE				512



//////////////////////////////////////////////////////////////////////
// 
// Virtual HUB-related constant
// 
//////////////////////////////////////////////////////////////////////

#define	SE_HUB_MAC_ADDR_SIGN				0xAE					// Sign virtual HUB MAC address

// Traffic difference value
#define	TRAFFIC_DIFF_USER		0		// User
#define	TRAFFIC_DIFF_HUB		1		// Virtual HUB
#define	MAX_TRAFFIC_DIFF		30000	// Maximum number of items

// Type of HUB
#define	HUB_TYPE_STANDALONE			0	// Stand-alone HUB
#define	HUB_TYPE_FARM_STATIC		1	// Static HUB
#define	HUB_TYPE_FARM_DYNAMIC		2	// Dynamic HUB

// Related to delay, jitter, packet loss in the access list
#define	HUB_ACCESSLIST_DELAY_MAX	10000		// Maximum delay
#define	HUB_ACCESSLIST_JITTER_MAX	100			// Maximum jitter
#define	HUB_ACCESSLIST_LOSS_MAX		100			// Maximum packet loss

// Message related
#define	HUB_MAXMSG_LEN				20000		// The maximum number of characters in a message



//////////////////////////////////////////////////////////////////////
// 
// Type of user authentication
// 
//////////////////////////////////////////////////////////////////////

// Constant in the server-side
#define	AUTHTYPE_ANONYMOUS				0			// Anonymous authentication
#define	AUTHTYPE_PASSWORD				1			// Password authentication
#define	AUTHTYPE_USERCERT				2			// User certificate authentication
#define	AUTHTYPE_ROOTCERT				3			// Root certificate which is issued by trusted Certificate Authority
#define	AUTHTYPE_RADIUS					4			// Radius authentication
#define	AUTHTYPE_NT						5			// Windows NT authentication
#define	AUTHTYPE_OPENVPN_CERT    		98			// TLS client certificate authentication
#define	AUTHTYPE_TICKET					99			// Ticket authentication

// Constant of the client side
#define	CLIENT_AUTHTYPE_ANONYMOUS		0			// Anonymous authentication
#define	CLIENT_AUTHTYPE_PASSWORD		1			// Password authentication
#define	CLIENT_AUTHTYPE_PLAIN_PASSWORD	2			// Plain password authentication
#define	CLIENT_AUTHTYPE_CERT			3			// Certificate authentication
#define	CLIENT_AUTHTYPE_SECURE			4			// Secure device authentication



//////////////////////////////////////////////////////////////////////
// 
// TCP listener related constants
// 
//////////////////////////////////////////////////////////////////////

// Retries in case it fails to Listen
#define	LISTEN_RETRY_TIME			(2 * 1000)		// If fail to Listen normally
#define LISTEN_RETRY_TIME_NOIPV6	(60 * 1000)		// If IPv6 support is disabled

#define	DOS_TABLE_EXPIRES_FIRST		250				// Initial value of the expiration date of DOS attack list
#define	DOS_TABLE_EXPIRES_MAX		1000			// Maximum value of the expiration date of DOS attack list
#define	DOS_TABLE_REFRESH_INTERVAL	(10 * 1000)		// Interval to update the DOS attack list
#define	DOS_TABLE_MAX_LIMIT_PER_IP	16				// Accessible number per an IP
#define	DOS_TABLE_EXPIRES_TOTAL		(3000 * 1000)	// Time to force delete the entry


// Protocol to be used for the listener
#define	LISTENER_TCP				0		// TCP/IP
#define	LISTENER_UDP				1		// UDP/IP (not being used)
#define	LISTENER_INPROC				2		// In-process communication
#define	LISTENER_RUDP				3		// R-UDP with NAT-T
#define	LISTENER_ICMP				4		// VPN over ICMP
#define	LISTENER_DNS				5		// VPN over DNS
#define	LISTENER_REVERSE			6		// Reverse socket

// Status of the listener
#define	LISTENER_STATUS_TRYING		0		// While attempting
#define	LISTENER_STATUS_LISTENING	1		// Listening

// Largest packet size of UDP
#define	UDP_PACKET_SIZE				65536

// Number of standard connections per IP address
#define DEFAULT_MAX_CONNECTIONS_PER_IP	256
#define MIN_MAX_CONNECTIONS_PER_IP	10		// Minimum value

// Allowed number of outstanding connections
#define	DEFAULT_MAX_UNESTABLISHED_CONNECTIONS	1000
#define	MIN_MAX_UNESTABLISHED_CONNECTIONS	30	// Minimum value


//////////////////////////////////////////////////////////////////////
// 
// Log related constant
// 
//////////////////////////////////////////////////////////////////////

#define	LOG_ENGINE_SAVE_START_CACHE_COUNT	100000		// Number to start saving forcibly
#define	LOG_ENGINE_BUFFER_CACHE_SIZE_MAX	(10 * 1024 * 1024)	// Write cache size

// Constant such as a file name
//
// These placeholders will be replaced in InnerFilePathW().
//
// @ - placeholder for LogDir
// $ - placeholder for DbDir (config directory)
//
#define	SERVER_LOG_DIR				"server_log"
#define	SERVER_LOG_DIR_NAME			"@"SERVER_LOG_DIR
#define	BRIDGE_LOG_DIR_NAME			SERVER_LOG_DIR_NAME
#define	SERVER_LOG_PERFIX			"vpn"

#define	HUB_SECURITY_LOG_DIR		"security_log"
#define	HUB_SECURITY_LOG_DIR_NAME	"@"HUB_SECURITY_LOG_DIR
#define	HUB_SECURITY_LOG_FILE_NAME	HUB_SECURITY_LOG_DIR_NAME"/%s"
#define	HUB_SECURITY_LOG_PREFIX		"sec"
#define	HUB_PACKET_LOG_DIR		"packet_log"
#define	HUB_PACKET_LOG_DIR_NAME		"@"HUB_PACKET_LOG_DIR
#define	HUB_PACKET_LOG_FILE_NAME	HUB_PACKET_LOG_DIR_NAME"/%s"
#define	HUB_PACKET_LOG_PREFIX		"pkt"

#define	NAT_LOG_DIR				"secure_nat_log"
#define	NAT_LOG_DIR_NAME			"@"NAT_LOG_DIR
#define	NAT_LOG_FILE_NAME			NAT_LOG_DIR_NAME"/%s"
#define	NAT_LOG_PREFIX				"snat"

#define	CLIENT_LOG_DIR_NAME			"@client_log"
#define	CLIENT_LOG_PREFIX			"client"

// Packet log settings
#define	NUM_PACKET_LOG				16
#define	PACKET_LOG_TCP_CONN			0		// TCP connection log
#define	PACKET_LOG_TCP				1		// TCP packet log
#define	PACKET_LOG_DHCP				2		// DHCP Log
#define	PACKET_LOG_UDP				3		// UDP log
#define	PACKET_LOG_ICMP				4		// ICMP log
#define	PACKET_LOG_IP				5		// IP log
#define	PACKET_LOG_ARP				6		// ARP log
#define	PACKET_LOG_ETHERNET			7		// Ethernet log

#define	PACKET_LOG_NONE				0		// Not save
#define	PACKET_LOG_HEADER			1		// Only header
#define	PACKET_LOG_ALL				2		// Store also data

// Timing of log switching
#define	LOG_SWITCH_NO				0		// No switching
#define	LOG_SWITCH_SECOND			1		// Secondly basis
#define	LOG_SWITCH_MINUTE			2		// Minutely basis
#define	LOG_SWITCH_HOUR				3		// Hourly basis
#define	LOG_SWITCH_DAY				4		// Daily basis
#define	LOG_SWITCH_MONTH			5		// Monthly basis

// Minimum amount of free disk space
#define	DISK_FREE_SPACE_MIN			1048576	// 1 MBytes
#define	DISK_FREE_SPACE_DEFAULT		(DISK_FREE_SPACE_MIN * 100)	// 100 Mbytes
#define	DISK_FREE_SPACE_DEFAULT_WINDOWS	((UINT64)(8ULL * 1024ULL * 1024ULL * 1024ULL))	// 8GBytes

// Interval to check the free space
#define	DISK_FREE_CHECK_INTERVAL_DEFAULT	(5 * 60 * 1000)

// Simple log
#define TINY_LOG_DIRNAME			"@tiny_log"
#define TINY_LOG_FILENAME			"@tiny_log/%04u%02u%02u_%02u%02u%02u.log"


//////////////////////////////////////////////////////////////////////
// 
// Constant related to Carrier Edition
// 
//////////////////////////////////////////////////////////////////////

#define CE_SNAPSHOT_INTERVAL		((UINT64)(3600 * 1000))
//#define CE_SNAPSHOT_INTERVAL		((UINT64)(3000))
#define CE_SNAPSHOT_POLLING_INTERVAL	(1 * 1000)
#define CE_SNAPSHOT_POLLING_INTERVAL_LICENSE	(30 * 1000)
#define CE_SNAPSHOT_DIR_NAME		"@carrier_log"
#define CE_SNAPSHOT_PREFIX			"carrier"


//////////////////////////////////////////////////////////////////////
// 
// Communication protocol related constant
// 
//////////////////////////////////////////////////////////////////////

// Administrator Username
#define	ADMINISTRATOR_USERNAME		"administrator"
// Maximum value of random size
#define	RAND_SIZE_MAX				4096
// Expiration date of random size cache
#define	RAND_SIZE_CACHE_EXPIRE		(24 * 60 * 60 * 1000)
// Management allowed IP address list file name
#define	ADMINIP_TXT					"$adminip.txt"

#define NON_SSL_MIN_COUNT			60
#define NON_SSL_ENTRY_EXPIRES		(10 * 60 * 1000)

//////////////////////////////////////////////////////////////////////
// 
// The cascade related constants
// 
//////////////////////////////////////////////////////////////////////

#define	LINK_DEVICE_NAME		"_SEHUBLINKCLI_"
#define	LINK_USER_NAME			"link"
#define	LINK_USER_NAME_PRINT	"Cascade"



//////////////////////////////////////////////////////////////////////
// 
// Constant related to SecureNAT connection
// 
//////////////////////////////////////////////////////////////////////

#define	SNAT_DEVICE_NAME		"_SEHUBSECURENAT_"
#define	SNAT_USER_NAME			"securenat"
#define	SNAT_USER_NAME_PRINT	"SecureNAT"



//////////////////////////////////////////////////////////////////////
// 
// Constant related to bridge connection
// 
//////////////////////////////////////////////////////////////////////

#define	BRIDGE_DEVICE_NAME				"_SEHUBBRIDGE_"
#define	BRIDGE_USER_NAME				"localbridge"
#define	BRIDGE_USER_NAME_PRINT			"Local Bridge"
#define	BRIDGE_TRY_SPAN					1000
#define	BRIDGE_NUM_DEVICE_CHECK_SPAN	(5 * 60 * 1000)
#define BRIDGE_NETWORK_CONNECTION_STR	L"%s [%S]"



//////////////////////////////////////////////////////////////////////
// 
// EtherLogger related constants
// 
//////////////////////////////////////////////////////////////////////

#define	EL_ADMIN_PORT			22888
#define	EL_CONFIG_FILENAME		"$etherlogger.config"
#define	EL_PACKET_LOG_DIR	"etherlogger_log"
#define	EL_PACKET_LOG_DIR_NAME	"@"EL_PACKET_LOG_DIR
#define	EL_PACKET_LOG_FILE_NAME	EL_PACKET_LOG_DIR_NAME"/%s"
#define	EL_PACKET_LOG_PREFIX	"pkt"
#define	EL_LICENSE_CHECK_SPAN	(10 * 1000)



//////////////////////////////////////////////////////////////////////
// 
// Layer-3 Switch related constants
// 
//////////////////////////////////////////////////////////////////////

#define	MAX_NUM_L3_SWITCH		4096
#define	MAX_NUM_L3_IF			4096
#define	MAX_NUM_L3_TABLE		4096



//////////////////////////////////////////////////////////////////////
// 
// Constant related to User-mode Router
// 
//////////////////////////////////////////////////////////////////////

#define	ARP_ENTRY_EXPIRES			(30 * 1000)		// ARP table expiration date
#define	ARP_ENTRY_POLLING_TIME		(1 * 1000)		// ARP table cleaning timer
#define	ARP_REQUEST_TIMEOUT			(1000)			// ARP request time-out period
#define	ARP_REQUEST_GIVEUP			(5 * 1000)		// Time to give up sending the ARP request
#define	IP_WAIT_FOR_ARP_TIMEOUT		(5 * 1000)		// Total time that an IP packet waiting for ARP table
#define	IP_COMBINE_TIMEOUT			(10 * 1000)		// Time-out of IP packet combining
#define	NAT_TCP_MAX_TIMEOUT			(2000000 * 1000)	// Maximum TCP session timeout in seconds
#define	NAT_UDP_MAX_TIMEOUT			(2000000 * 1000)	// Maximum UDP session timeout in seconds
#define	NAT_TCP_MIN_TIMEOUT			(1 * 60 * 1000)		// Minimum TCP session timeout in seconds
#define	NAT_UDP_MIN_TIMEOUT			(10 * 1000)			// Minimum UDP session timeout in seconds
#define	NAT_TCP_RECV_WINDOW_SIZE	64512				// TCP receive window size
#define	NAT_TCP_SYNACK_SEND_TIMEOUT	250					// Sending TCP SYN+ACK interval
#define	NAT_ICMP_TIMEOUT			(10 * 1000)			// ICMP timeout in seconds
#define	NAT_ICMP_TIMEOUT_WITH_API	(3 * 1000)			// Timeout in seconds in the case of using the ICMP API
#define	NAT_SEND_BUF_SIZE			(64 * 1024)			// TCP send buffer size
#define	NAT_RECV_BUF_SIZE			(64 * 1024)			// TCP receive buffer size
#define	NAT_TMPBUF_SIZE				(128 * 1024)		// TCP temporally memory area size
#define	NAT_ACK_KEEPALIVE_SPAN		(5 * 1000)			// ACK transmission interval for TCP keep alive
#define	NAT_INITIAL_RTT_VALUE		500					// Initial RTT value
#define	NAT_FIN_SEND_INTERVAL		1000				// FIN transmission interval
#define	NAT_FIN_SEND_MAX_COUNT		5					// Total number of FIN transmissions
#define	NAT_DNS_PROXY_PORT			53					// DNS proxy port number
#define	NAT_DNS_RESPONSE_TTL		(20 * 60)			// TTL of the DNS response
#define	NAT_DHCP_SERVER_PORT		67					// DHCP server port number
#define	NAT_DHCP_CLIENT_PORT		68					// DHCP client port number
#define	DHCP_MIN_EXPIRE_TIMESPAN	(15 * 1000)			// DHCP minimum expiration date
#define	DHCP_POLLING_INTERVAL		1000				// DHCP polling interval
#define	X32							((UINT64)4294967296ULL)	// 32bit + 1
#define	NAT_DNS_QUERY_TIMEOUT		(512)				// Time-out value of DNS queries

// Beacon transmission interval
#define	BEACON_SEND_INTERVAL		(5 * 1000)

// Total size quota allowed in the queue for the combining the IP packet
#define	IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA	(50 * 1024 * 1024)

// Header size constant
#define	MAC_HEADER_SIZE				(sizeof(MAC_HEADER))
#define	ARP_HEADER_SIZE				(sizeof(ARP_HEADER))
#define	IP_HEADER_SIZE				(sizeof(IPV4_HEADER))
#define	TCP_HEADER_SIZE				(sizeof(TCP_HEADER))
#define	UDP_HEADER_SIZE				(sizeof(UDP_HEADER))

// Data maximum size constant
#define	MAX_L3_DATA_SIZE			(1500)
#define	MAX_IP_DATA_SIZE			(MAX_L3_DATA_SIZE - IP_HEADER_SIZE)
#define	MAX_TCP_DATA_SIZE			(MAX_IP_DATA_SIZE - TCP_HEADER_SIZE)
#define	MAX_UDP_DATA_SIZE			(MAX_IP_DATA_SIZE - UDP_HEADER_SIZE)
#define	MAX_IP_DATA_SIZE_TOTAL		(65535)

// IP packet option constant
#define	DEFAULT_IP_TOS				0				// TOS in the IP header
#define	DEFAULT_IP_TTL				128				// TTL in the IP header

// Type of NAT session
#define	NAT_TCP						0		// TCP NAT
#define	NAT_UDP						1		// UDP NAT
#define	NAT_DNS						2		// DNS NAT
#define	NAT_ICMP					3		// ICMP NAT

// State of NAT session
#define	NAT_TCP_CONNECTING			0		// Connecting
#define	NAT_TCP_SEND_RESET			1		// Send the RST (Connection failure or disconnected)
#define	NAT_TCP_CONNECTED			2		// Connection complete
#define	NAT_TCP_ESTABLISHED			3		// Connection established
#define	NAT_TCP_WAIT_DISCONNECT		4		// Wait for socket disconnection


//////////////////////////////////////////////////////////////////////
// 
// For UNIX virtual LAN card related constant
// 
//////////////////////////////////////////////////////////////////////

#ifndef	UNIX_BSD
#define	TAP_FILENAME_1				"/dev/net/tun"
#define	TAP_FILENAME_2				"/dev/tun"
#else	// UNIX_BSD
#define	TAP_NAME					"tap"
#define	TAP_DIR						"/dev/"
#define	TAP_MAX						(512)
#endif	// UNIX_BSD


#define	LICENSE_EDITION_VPN3_NO_LICENSE					0		// Without license

#define	LICENSE_MAX_PRODUCT_NAME_LEN	255				// Maximum length of license product name
#define	LICENSE_NUM_SHA					10000			// Number of times to hash with SHA
#define	LICENSE_SYSTEM_KEY_NUM			2048			// Key number for system
#define	LICENSE_SYSTEM_KEYSIZE_BIT		144				// Number of key bits for system
#define	LICENSE_PRODUCT_KEY_NUM			16384			// Number of keys for product
#define	LICENSE_PRODUCT_KEYSIZE_BIT		56				// Number of key bits for product
#define	LICENSE_PRODUCT_COMMON_KEYSIZE_BIT	48			// Number of common key bits for product
#define	LICENSE_MASTER_KEYSIZE_BIT		1024			// Number of master key bits
#define	LICENSE_SYSTEM_ID_MIN			0ULL			// System ID minimum value
#define	LICENSE_SYSTEM_ID_MAX			549755813887ULL	// System ID maximum value
#define	LICENSE_SERIAL_ID_MIN			0				// Serial ID minimum value
#define	LICENSE_SERIAL_ID_MAX			65535			// Serial ID maximum value
#define	LICENSE_EXPIRES_MIN				0				// Expiration date minimum
#define	LICENSE_EXPIRES_MAX				16383			// Expiration date maximum
#define	LICENSE_KEYSTR_LEN				41				// Length of the license key
#define	LICENSE_LICENSEID_STR_LEN		33				// Length of the license ID

#define	LICENSE_STATUS_OK				0		// Enabled
#define	LICENSE_STATUS_EXPIRED			1		// Invalid (expired)
#define	LICENSE_STATUS_ID_DIFF			2		// Invalid (System ID mismatch)
#define	LICENSE_STATUS_DUP				3		// Invalid (duplicated)
#define	LICENSE_STATUS_INSUFFICIENT		4		// Invalid (other necessary license shortage)
#define	LICENSE_STATUS_COMPETITION		5		// Invalid (conflict with other licenses)
#define	LICENSE_STATUS_NONSENSE			6		// Invalid (meaningless in the current edition)
#define	LICENSE_STATUS_CPU				7		// Invalid (CPU type mismatch)

#define	BIT_TO_BYTE(x)					(((x) + 7) / 8)
#define	BYTE_TO_BIT(x)					((x) * 8)


//////////////////////////////////////////////////////////////////////
// 
// Error code
// 
//////////////////////////////////////////////////////////////////////

#define	ERR_NO_ERROR					0	// No error
#define	ERR_CONNECT_FAILED				1	// Connection to the server has failed
#define	ERR_SERVER_IS_NOT_VPN			2	// The destination server is not a VPN server
#define	ERR_DISCONNECTED				3	// The connection has been interrupted
#define	ERR_PROTOCOL_ERROR				4	// Protocol error
#define	ERR_CLIENT_IS_NOT_VPN			5	// Connecting client is not a VPN client
#define	ERR_USER_CANCEL					6	// User cancel
#define	ERR_AUTHTYPE_NOT_SUPPORTED		7	// Specified authentication method is not supported
#define	ERR_HUB_NOT_FOUND				8	// The HUB does not exist
#define	ERR_AUTH_FAILED					9	// Authentication failure
#define	ERR_HUB_STOPPING				10	// HUB is stopped
#define	ERR_SESSION_REMOVED				11	// Session has been deleted
#define	ERR_ACCESS_DENIED				12	// Access denied
#define	ERR_SESSION_TIMEOUT				13	// Session times out
#define	ERR_INVALID_PROTOCOL			14	// Protocol is invalid
#define	ERR_TOO_MANY_CONNECTION			15	// Too many connections
#define	ERR_HUB_IS_BUSY					16	// Too many sessions of the HUB
#define	ERR_PROXY_CONNECT_FAILED		17	// Connection to the proxy server fails
#define	ERR_PROXY_ERROR					18	// Proxy Error
#define	ERR_PROXY_AUTH_FAILED			19	// Failed to authenticate on the proxy server
#define	ERR_TOO_MANY_USER_SESSION		20	// Too many sessions of the same user
#define	ERR_LICENSE_ERROR				21	// License error
#define	ERR_DEVICE_DRIVER_ERROR			22	// Device driver error
#define	ERR_INTERNAL_ERROR				23	// Internal error
#define	ERR_SECURE_DEVICE_OPEN_FAILED	24	// The secure device cannot be opened
#define	ERR_SECURE_PIN_LOGIN_FAILED		25	// PIN code is incorrect
#define	ERR_SECURE_NO_CERT				26	// Specified certificate is not stored
#define	ERR_SECURE_NO_PRIVATE_KEY		27	// Specified private key is not stored
#define	ERR_SECURE_CANT_WRITE			28	// Write failure
#define	ERR_OBJECT_NOT_FOUND			29	// Specified object can not be found
#define	ERR_VLAN_ALREADY_EXISTS			30	// Virtual LAN card with the specified name already exists
#define	ERR_VLAN_INSTALL_ERROR			31	// Specified virtual LAN card cannot be created
#define	ERR_VLAN_INVALID_NAME			32	// Specified name of the virtual LAN card is invalid
#define	ERR_NOT_SUPPORTED				33	// Unsupported
#define	ERR_ACCOUNT_ALREADY_EXISTS		34	// Account already exists
#define	ERR_ACCOUNT_ACTIVE				35	// Account is operating
#define	ERR_ACCOUNT_NOT_FOUND			36	// Specified account doesn't exist
#define	ERR_ACCOUNT_INACTIVE			37	// Account is offline
#define	ERR_INVALID_PARAMETER			38	// Parameter is invalid
#define	ERR_SECURE_DEVICE_ERROR			39	// Error has occurred in the operation of the secure device
#define	ERR_NO_SECURE_DEVICE_SPECIFIED	40	// Secure device is not specified
#define	ERR_VLAN_IS_USED				41	// Virtual LAN card in use by account
#define	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND	42	// Virtual LAN card of the account can not be found
#define	ERR_VLAN_FOR_ACCOUNT_USED		43	// Virtual LAN card of the account is already in use
#define	ERR_VLAN_FOR_ACCOUNT_DISABLED	44	// Virtual LAN card of the account is disabled
#define	ERR_INVALID_VALUE				45	// Value is invalid
#define	ERR_NOT_FARM_CONTROLLER			46	// Not a farm controller
#define	ERR_TRYING_TO_CONNECT			47	// Attempting to connect
#define	ERR_CONNECT_TO_FARM_CONTROLLER	48	// Failed to connect to the farm controller
#define	ERR_COULD_NOT_HOST_HUB_ON_FARM	49	// A virtual HUB on farm could not be created
#define	ERR_FARM_MEMBER_HUB_ADMIN		50	// HUB cannot be managed on a farm member
#define	ERR_NULL_PASSWORD_LOCAL_ONLY	51	// Accepting only local connections for an empty password
#define	ERR_NOT_ENOUGH_RIGHT			52	// Right is insufficient
#define	ERR_LISTENER_NOT_FOUND			53	// Listener can not be found
#define	ERR_LISTENER_ALREADY_EXISTS		54	// Listener already exists
#define	ERR_NOT_FARM_MEMBER				55	// Not a farm member
#define	ERR_CIPHER_NOT_SUPPORTED		56	// Encryption algorithm is not supported
#define	ERR_HUB_ALREADY_EXISTS			57	// HUB already exists
#define	ERR_TOO_MANY_HUBS				58	// Too many HUBs
#define	ERR_LINK_ALREADY_EXISTS			59	// Link already exists
#define	ERR_LINK_CANT_CREATE_ON_FARM	60	// The link can not be created on the server farm
#define	ERR_LINK_IS_OFFLINE				61	// Link is off-line
#define	ERR_TOO_MANY_ACCESS_LIST		62	// Too many access list
#define	ERR_TOO_MANY_USER				63	// Too many users
#define	ERR_TOO_MANY_GROUP				64	// Too many Groups
#define	ERR_GROUP_NOT_FOUND				65	// Group can not be found
#define	ERR_USER_ALREADY_EXISTS			66	// User already exists
#define	ERR_GROUP_ALREADY_EXISTS		67	// Group already exists
#define	ERR_USER_AUTHTYPE_NOT_PASSWORD	68	// Authentication method of the user is not a password authentication
#define	ERR_OLD_PASSWORD_WRONG			69	// The user does not exist or the old password is wrong
#define	ERR_LINK_CANT_DISCONNECT		73	// Cascade session cannot be disconnected
#define	ERR_ACCOUNT_NOT_PRESENT			74	// Not completed configure the connection to the VPN server
#define	ERR_ALREADY_ONLINE				75	// It is already online
#define	ERR_OFFLINE						76	// It is offline
#define	ERR_NOT_RSA_1024				77	// The certificate is not RSA 1024bit
#define	ERR_SNAT_CANT_DISCONNECT		78	// SecureNAT session cannot be disconnected
#define	ERR_SNAT_NEED_STANDALONE		79	// SecureNAT works only in stand-alone HUB
#define	ERR_SNAT_NOT_RUNNING			80	// SecureNAT function is not working
#define	ERR_SE_VPN_BLOCK				81	// Stopped by PacketiX VPN Block
#define	ERR_BRIDGE_CANT_DISCONNECT		82	// Bridge session can not be disconnected
#define	ERR_LOCAL_BRIDGE_STOPPING		83	// Bridge function is stopped
#define	ERR_LOCAL_BRIDGE_UNSUPPORTED	84	// Bridge feature is not supported
#define	ERR_CERT_NOT_TRUSTED			85	// Certificate of the destination server can not be trusted
#define	ERR_PRODUCT_CODE_INVALID		86	// Product code is different
#define	ERR_VERSION_INVALID				87	// Version is different
#define	ERR_CAPTURE_DEVICE_ADD_ERROR	88	// Adding capture device failure
#define	ERR_VPN_CODE_INVALID			89	// VPN code is different
#define	ERR_CAPTURE_NOT_FOUND			90	// Capture device can not be found
#define	ERR_LAYER3_CANT_DISCONNECT		91	// Layer-3 session cannot be disconnected
#define	ERR_LAYER3_SW_EXISTS			92	// L3 switch of the same already exists
#define	ERR_LAYER3_SW_NOT_FOUND			93	// Layer-3 switch can not be found
#define	ERR_INVALID_NAME				94	// Name is invalid
#define	ERR_LAYER3_IF_ADD_FAILED		95	// Failed to add interface
#define	ERR_LAYER3_IF_DEL_FAILED		96	// Failed to delete the interface
#define	ERR_LAYER3_IF_EXISTS			97	// Interface that you specified already exists
#define	ERR_LAYER3_TABLE_ADD_FAILED		98	// Failed to add routing table
#define	ERR_LAYER3_TABLE_DEL_FAILED		99	// Failed to delete the routing table
#define	ERR_LAYER3_TABLE_EXISTS			100	// Routing table entry that you specified already exists
#define	ERR_BAD_CLOCK					101	// Time is queer
#define	ERR_LAYER3_CANT_START_SWITCH	102	// The Virtual Layer 3 Switch can not be started
#define	ERR_CLIENT_LICENSE_NOT_ENOUGH	103	// Client connection licenses shortage
#define	ERR_BRIDGE_LICENSE_NOT_ENOUGH	104 // Bridge connection licenses shortage
#define	ERR_SERVER_CANT_ACCEPT			105	// Not Accept on the technical issues
#define	ERR_SERVER_CERT_EXPIRES			106	// Destination VPN server has expired
#define	ERR_MONITOR_MODE_DENIED			107	// Monitor port mode was rejected
#define	ERR_BRIDGE_MODE_DENIED			108	// Bridge-mode or Routing-mode was rejected
#define	ERR_IP_ADDRESS_DENIED			109	// Client IP address is denied
#define	ERR_TOO_MANT_ITEMS				110	// Too many items
#define	ERR_MEMORY_NOT_ENOUGH			111	// Out of memory
#define	ERR_OBJECT_EXISTS				112	// Object already exists
#define	ERR_FATAL						113	// A fatal error occurred
#define	ERR_SERVER_LICENSE_FAILED		114	// License violation has occurred on the server side
#define	ERR_SERVER_INTERNET_FAILED		115	// Server side is not connected to the Internet
#define	ERR_CLIENT_LICENSE_FAILED		116	// License violation occurs on the client side
#define	ERR_BAD_COMMAND_OR_PARAM		117	// Command or parameter is invalid
#define	ERR_INVALID_LICENSE_KEY			118	// License key is invalid
#define	ERR_NO_VPN_SERVER_LICENSE		119	// There is no valid license for the VPN Server
#define	ERR_NO_VPN_CLUSTER_LICENSE		120	// There is no cluster license
#define ERR_NOT_ADMINPACK_SERVER		121	// Not trying to connect to a server with the Administrator Pack license
#define ERR_NOT_ADMINPACK_SERVER_NET	122	// Not trying to connect to a server with the Administrator Pack license (for .NET)
#define ERR_BETA_EXPIRES				123	// Destination Beta VPN Server has expired
#define ERR_BRANDED_C_TO_S				124 // Branding string of connection limit is different (Authentication on the server side)
#define ERR_BRANDED_C_FROM_S			125	// Branding string of connection limit is different (Authentication for client-side)
#define	ERR_AUTO_DISCONNECTED			126	// VPN session is disconnected for a certain period of time has elapsed
#define	ERR_CLIENT_ID_REQUIRED			127	// Client ID does not match
#define	ERR_TOO_MANY_USERS_CREATED		128	// Too many created users
#define	ERR_SUBSCRIPTION_IS_OLDER		129	// Subscription expiration date Is earlier than the build date of the VPN Server
#define	ERR_ILLEGAL_TRIAL_VERSION		130	// Many trial license is used continuously
#define	ERR_NAT_T_TWO_OR_MORE			131	// There are multiple servers in the back of a global IP address in the NAT-T connection
#define	ERR_DUPLICATE_DDNS_KEY			132	// DDNS host key duplicate
#define	ERR_DDNS_HOSTNAME_EXISTS		133	// Specified DDNS host name already exists
#define	ERR_DDNS_HOSTNAME_INVALID_CHAR	134	// Characters that can not be used for the host name is included
#define	ERR_DDNS_HOSTNAME_TOO_LONG		135	// Host name is too long
#define	ERR_DDNS_HOSTNAME_IS_EMPTY		136	// Host name is not specified
#define	ERR_DDNS_HOSTNAME_TOO_SHORT		137	// Host name is too short
#define	ERR_MSCHAP2_PASSWORD_NEED_RESET	138	// Necessary that password is changed
#define	ERR_DDNS_DISCONNECTED			139	// Communication to the dynamic DNS server is disconnected
#define	ERR_SPECIAL_LISTENER_ICMP_ERROR	140	// The ICMP socket can not be opened
#define	ERR_SPECIAL_LISTENER_DNS_ERROR	141	// Socket for DNS port can not be opened
#define	ERR_OPENVPN_IS_NOT_ENABLED		142	// OpenVPN server feature is not enabled
#define	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE	143	// It is the type of user authentication that are not supported in the open source version
#define	ERR_VPNGATE						144 // Operation on VPN Gate Server is not available
#define	ERR_VPNGATE_CLIENT				145 // Operation on VPN Gate Client is not available
#define	ERR_VPNGATE_INCLIENT_CANT_STOP	146	// Can not be stopped if operating within VPN Client mode
#define	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE	147	// It is a feature that is not supported in the open source version
#define	ERR_SUSPENDING					148	// System is suspending


////////////////////////////
// Generally used structure

// Network Services
typedef struct NETSVC
{
	bool Udp;						// false=TCP, true=UDP
	UINT Port;						// Port number
	char *Name;						// Name
} NETSVC;

// Traffic data entry
typedef struct TRAFFIC_ENTRY
{
	UINT64 BroadcastCount;			// Number of broadcast packets
	UINT64 BroadcastBytes;			// Broadcast bytes
	UINT64 UnicastCount;			// Unicast count
	UINT64 UnicastBytes;			// Unicast bytes
} TRAFFIC_ENTRY;

// Traffic data
typedef struct TRAFFIC
{
	TRAFFIC_ENTRY Send;				// Transmitted data
	TRAFFIC_ENTRY Recv;				// Received data
} TRAFFIC;

// Non-SSL connection source
typedef struct NON_SSL
{
	IP IpAddress;					// IP address
	UINT64 EntryExpires;			// Expiration date of entry
	UINT Count;						// Number of connection count
} NON_SSL;

// Simple log storage
typedef struct TINY_LOG
{
	char FileName[MAX_PATH];		// File name
	IO *io;							// File
	LOCK *Lock;						// Lock
} TINY_LOG;

// CEDAR structure
typedef struct CEDAR
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	COUNTER *AcceptingSockets;		// Number of sockets in Accept
	UINT Type;						// Type
	LIST *ListenerList;				// Listener list
	LIST *HubList;					// HUB list
	LIST *ConnectionList;			// Negotiating connection list
	LIST *CaList;					// List of CA
	volatile bool Halt;				// Halt flag
	COUNTER *ConnectionIncrement;	// Connection increment counter
	X *ServerX;						// Server certificate
	K *ServerK;						// Private key of the server certificate
	char UsernameHubSeparator;		// Character which separates the username from the hub name
	char *CipherList;				// List of encryption algorithms
	UINT Version;					// Version information
	UINT Build;						// Build Number
	char *ServerStr;				// Server string
	char *MachineName;				// Computer name
	char *HttpUserAgent;			// HTTP user agent
	char *HttpAccept;				// HTTP Accept
	char *HttpAcceptLanguage;		// HTTP Accept Language
	char *HttpAcceptEncoding;		// HTTP Accept Encoding
	TRAFFIC *Traffic;				// Traffic information
	LOCK *TrafficLock;				// Traffic information lock
	LIST *UDPEntryList;				// UDP entry list
	COUNTER *CurrentSessions;		// The current number of sessions
	COUNTER *CurrentTcpConnections;	// Number of current TCP connections
	LIST *NetSvcList;				// Network service list
	char *VerString;				// Version string
	char *BuildInfo;				// Build Information
	struct CLIENT *Client;			// Client
	struct SERVER *Server;			// Server
	UINT64 CreatedTick;				// Generation date and time
	bool CheckExpires;				// Check the expiration date
	LIST *TrafficDiffList;			// Traffic difference list
	struct LOG *DebugLog;			// Debug log
	UCHAR UniqueId[16];				// Unique ID
	LIST *LocalBridgeList;			// Local bridge list
	bool Bridge;					// Bridge version
	LIST *L3SwList;					// Layer-3 switch list
	COUNTER *AssignedClientLicense;	// Number of assigned client licenses
	COUNTER *AssignedBridgeLicense;	// Number of assigned bridge licenses
	UINT64 LicenseViolationTick;	// License violation occurs
	LIST *NonSslList;				// Non-SSL connection list
	struct WEBUI *WebUI;			// Data for WebUI service
	UINT Beta;						// Beta number
	LOCK *CedarSuperLock;			// Cedar super lock!
	bool DisableIPv6Listener;		// Disable IPv6 listener
	UINT ClientId;					// Client ID
	UINT64 BuiltDate;				// Build Date
	LIST *UdpPortList;				// UDP port list in use
	char CurrentDDnsFqdn[MAX_SIZE];	// FQDN of the current DDNS
	char OpenVPNPublicPorts[MAX_SIZE];	// OpenVPN public UDP port list
	LOCK *OpenVPNPublicPortsLock;	// Lock of OpenVPN public UDP port list
	LOCK *CurrentRegionLock;		// Current region lock
	char CurrentRegion[128];		// Current region
	LOCK *CurrentTcpQueueSizeLock;	// Current TCP send queue size lock
	UINT CurrentTcpQueueSize;		// Current TCP send queue size
	COUNTER *CurrentActiveLinks;	// Current active cascade connections
	LOCK *QueueBudgetLock;			// Queue budget lock
	UINT QueueBudget;				// Queue budget
	LOCK *FifoBudgetLock;			// Fifo budget lock
	UINT FifoBudget;				// Fifo budget
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	UINT DhParamBits;  // Bits of Diffie-Hellman parameters
} CEDAR;

// Type of CEDAR
#define	CEDAR_CLIENT				0	// Client
#define	CEDAR_STANDALONE_SERVER		1	// Stand-alone server
#define	CEDAR_FARM_CONTROLLER		2	// Server farm controller
#define	CEDAR_FARM_MEMBER			3	// Server farm member


////////////////////////////
// Read the header file

// Type
#include <Cedar/CedarType.h>
// Account Manager
#include <Cedar/Account.h>
// Listener module
#include <Cedar/Listener.h>
// Log storage module
#include <Cedar/Logging.h>
// Connection management
#include <Cedar/Connection.h>
// Session Management
#include <Cedar/Session.h>
// RPC
#include <Cedar/Remote.h>
// HUB management
#include <Cedar/Hub.h>
// Security Accounts Manager
#include <Cedar/Sam.h>
// Radius authentication module
#include <Cedar/Radius.h>
// Native protocol
#include <Cedar/Protocol.h>
// Inter-HUB link
#include <Cedar/Link.h>
// User-mode virtual host
#include <Cedar/Virtual.h>
// SecureNAT
#include <Cedar/SecureNAT.h>
// Digital watermark
#include <Cedar/WaterMark.h>
// Secure data
#include <Cedar/SecureInfo.h>
// Console service
#include <Cedar/Console.h>
// Vpncmd utility
#include <Cedar/Command.h>
// RPC over HTTP
#include <Cedar/Wpc.h>
// Layer-2/Layer-3 converter
#include <Cedar/IPC.h>
// Third party protocols
#include <Cedar/Proto.h>
#include <Cedar/Proto_IPsec.h>
#include <Cedar/Proto_EtherIP.h>
#include <Cedar/Proto_IkePacket.h>
#include <Cedar/Proto_IKE.h>
#include <Cedar/Proto_L2TP.h>
#include <Cedar/Proto_OpenVPN.h>
#include <Cedar/Proto_PPP.h>
#include <Cedar/Proto_SSTP.h>
#include <Cedar/Proto_Win7.h>
// UDP Acceleration
#include <Cedar/UdpAccel.h>
// DDNS Client
#include <Cedar/DDNS.h>
// VPN Azure Client
#include <Cedar/AzureClient.h>
// VPN Azure Server
#include <Cedar/AzureServer.h>
// Native IP Stack
#include <Cedar/NativeStack.h>

#ifdef	OS_WIN32
// Neo device driver
#include <Neo/Neo.h>
// SeLow User-mode
#include <Cedar/SeLowUser.h>
#endif	// OS_WIN32

// Neo device driver manipulation library
#include <Cedar/VLan.h>
// Bridge
#include <Cedar/Bridge.h>
// Layer-3 switch
#include <Cedar/Layer3.h>
// Virtual LAN card for test
#include <Cedar/NullLan.h>
// Client
#include <Cedar/Client.h>
// Server
#include <Cedar/Server.h>
// License database
#include <Cedar/Database.h>
// EtherLogger
#include <Cedar/EtherLog.h>
// Management RPC
#include <Cedar/Admin.h>
// User-mode Router
#include <Cedar/Nat.h>

// Web UI
#include <Cedar/WebUI.h>

// VPN Gate Main Implementation
#include <Cedar/VG.h>


#ifdef	OS_WIN32

// Win32 user interface
#include <Cedar/WinUi.h>
// Win32 Client Connection Manager
#include <Cedar/CM.h>
// Win32 Server Manager
#include <Cedar/SM.h>
// Win32 User-mode Router Manager
#include <Cedar/NM.h>
// Win32 EtherLogger Manager
#include <Cedar/EM.h>
// Win32 Network Utility
#include <Cedar/UT.h>
// Win32 Setup Wizard
#include <Cedar/SW.h>
// Win32 COM calling module
#include <Cedar/Win32Com.h>

#endif




////////////////////////////
// Function prototype

TRAFFIC *NewTraffic();
void FreeTraffic(TRAFFIC *t);
CEDAR *NewCedar(X *server_x, K *server_k);
void CedarForceLink();
void SetCedarVpnBridge(CEDAR *c);
void SetCedarCert(CEDAR *c, X *server_x, K *server_k);
void ReleaseCedar(CEDAR *c);
void CleanupCedar(CEDAR *c);
void StopCedar(CEDAR *c);
void AddListener(CEDAR *c, LISTENER *r);
void StopAllListener(CEDAR *c);
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff);
void AddHub(CEDAR *c, HUB *h);
void DelHub(CEDAR *c, HUB *h);
void DelHubEx(CEDAR *c, HUB *h, bool no_lock);
void StopAllHub(CEDAR *c);
void StopAllConnection(CEDAR *c);
void AddConnection(CEDAR *cedar, CONNECTION *c);
void DelConnection(CEDAR *cedar, CONNECTION *c);
void SetCedarCipherList(CEDAR *cedar, char *name);
void InitCedar();
void FreeCedar();
void AddCa(CEDAR *cedar, X *x);
bool DeleteCa(CEDAR *cedar, UINT ptr);
bool CheckSignatureByCa(CEDAR *cedar, X *x);
bool CheckSignatureByCaLinkMode(SESSION *s, X *x);
X *FindCaSignedX(LIST *o, X *x);
void InitNetSvcList(CEDAR *cedar);
void FreeNetSvcList(CEDAR *cedar);
int CompareNetSvc(void *p1, void *p2);
char *GetSvcName(CEDAR *cedar, bool udp, UINT port);
UINT64 GetTrafficPacketSize(TRAFFIC *t);
UINT64 GetTrafficPacketNum(TRAFFIC *t);
void StartCedarLog();
void StopCedarLog();
int CompareNoSslList(void *p1, void *p2);
void InitNoSslList(CEDAR *c);
void FreeNoSslList(CEDAR *c);
bool AddNoSsl(CEDAR *c, IP *ip);
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec);
void DeleteOldNoSsl(CEDAR *c);
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip);
void FreeTinyLog(TINY_LOG *t);
void WriteTinyLog(TINY_LOG *t, char *str);
TINY_LOG *NewTinyLog();
void GetWinVer(RPC_WINVER *v);
bool IsSupportedWinVer(RPC_WINVER *v);
SOCK *GetInProcListeningSock(CEDAR *c);
SOCK *GetReverseListeningSock(CEDAR *c);
void GetCedarVersion(char *tmp, UINT size);
UINT GetCedarVersionNumber();
UINT64 GetCurrentBuildDate();
void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff);
UINT CedarGetCurrentTcpQueueSize(CEDAR *c);
void CedarAddQueueBudget(CEDAR *c, int diff);
void CedarAddFifoBudget(CEDAR *c, int diff);
UINT CedarGetQueueBudgetConsuming(CEDAR *c);
UINT CedarGetFifoBudgetConsuming(CEDAR *c);
UINT CedarGetQueueBudgetBalance(CEDAR *c);
UINT CedarGetFifoBudgetBalance(CEDAR *c);
bool CedarIsThereAnyEapEnabledRadiusConfig(CEDAR *c);



#endif	// CEDAR_H

