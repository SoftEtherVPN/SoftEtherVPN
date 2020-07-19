// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_SSTP.h
// Header of Proto_SSTP.c

#ifndef	PROTO_SSTP_H
#define	PROTO_SSTP_H

//// Constants
#define	SSTP_URI				"/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"		// SSTP HTTPS URI
#define	SSTP_VERSION_1			0x10							// SSTP Version 1.0
#define	MAX_SSTP_PACKET_SIZE	4096							// Maximum packet size
#define SSTP_IPC_CLIENT_NAME			"Microsoft SSTP VPN Client"
#define	SSTP_IPC_POSTFIX				"SSTP"
#define	SSTP_ECHO_SEND_INTERVAL_MIN		2500					// Transmission interval of Echo Request (minimum)
#define	SSTP_ECHO_SEND_INTERVAL_MAX		4792					// Transmission interval of Echo Request (maximum)
#define	SSTP_TIMEOUT					20 * 1000				// Communication time-out of SSTP (from default policy)

// SSTP Message Type
#define	SSTP_MSG_CALL_CONNECT_REQUEST				0x0001
#define	SSTP_MSG_CALL_CONNECT_ACK					0x0002
#define	SSTP_MSG_CALL_CONNECT_NAK					0x0003
#define	SSTP_MSG_CALL_CONNECTED						0x0004
#define	SSTP_MSG_CALL_ABORT							0x0005
#define	SSTP_MSG_CALL_DISCONNECT					0x0006
#define	SSTP_MSG_CALL_DISCONNECT_ACK				0x0007
#define	SSTP_MSG_ECHO_REQUEST						0x0008
#define	SSTP_MSG_ECHO_RESPONSE						0x0009

// SSTP Attribute ID
#define	SSTP_ATTRIB_NO_ERROR						0x00
#define	SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID		0x01
#define	SSTP_ATTRIB_STATUS_INFO						0x02
#define	SSTP_ATTRIB_CRYPTO_BINDING					0x03
#define	SSTP_ATTRIB_CRYPTO_BINDING_REQ				0x04

// Protocol ID
#define	SSTP_ENCAPSULATED_PROTOCOL_PPP				0x0001

// Hash Protocol Bitmask
#define	CERT_HASH_PROTOCOL_SHA1						0x01
#define	CERT_HASH_PROTOCOL_SHA256					0x02

// Status
#define	ATTRIB_STATUS_NO_ERROR						0x00000000
#define	ATTRIB_STATUS_DUPLICATE_ATTRIBUTE			0x00000001
#define	ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE		0x00000002
#define	ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH	0x00000003
#define	ATTRIB_STATUS_VALUE_NOT_SUPPORTED			0x00000004
#define	ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED		0x00000005
#define	ATTRIB_STATUS_RETRY_COUNT_EXCEEDED			0x00000006
#define	ATTRIB_STATUS_INVALID_FRAME_RECEIVED		0x00000007
#define	ATTRIB_STATUS_NEGOTIATION_TIMEOUT			0x00000008
#define	ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG	0x00000009
#define	ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING	0x0000000A
#define	ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG	0x0000000B

// State of SSTP Server
#define	SSTP_SERVER_STATUS_REQUEST_PENGING			0	// Connection incomplete
#define	SSTP_SERVER_STATUS_CONNECTED_PENDING		1	// Connection completed. Authentication incomplete
#define	SSTP_SERVER_STATUS_ESTABLISHED				2	// Connection completed. Communication available
#define	SSTP_SERVER_STATUS_NOT_INITIALIZED	INFINITE	// Connection not accepted yet.

// Length of Nonce
#define	SSTP_NONCE_SIZE								32	// 256 bits


//// Type

// SSTP Attribute
struct SSTP_ATTRIBUTE
{
	UCHAR AttributeId;
	UCHAR *Data;
	UINT DataSize;
	UINT TotalLength;
};

// SSTP Packet
struct SSTP_PACKET
{
	UCHAR Version;
	bool IsControl;
	UCHAR *Data;
	UINT DataSize;
	USHORT MessageType;
	LIST *AttributeList;
};

// SSTP Server
struct SSTP_SERVER
{
	CEDAR *Cedar;
	UINT64 Now;
	IP ClientIp, ServerIp;
	UINT ClientPort, ServerPort;
	char ClientHostName[MAX_HOST_NAME_LEN + 1];
	char ClientCipherName[MAX_SIZE];
	SOCK_EVENT *SockEvent;
	QUEUE *RecvQueue;						// Receive queue
	QUEUE *SendQueue;						// Transmission queue
	INTERRUPT_MANAGER *Interrupt;			// Interrupt manager
	bool Aborting;							// Forced disconnection flag
	bool AbortSent;							// Flag of whether to send the Abort
	bool AbortReceived;						// Flag of whether the Abort has been received
	bool Disconnecting;						// Disconnecting flag
	bool DisconnectSent;					// Flag of whether to send a Disconnect
	bool DisconnectRecved;					// Flag of whether a Disconnect has been received
	bool Disconnected;						// Flag as to disconnect
	UINT Status;							// State
	UCHAR SentNonce[SSTP_NONCE_SIZE];		// Random data sent
	TUBE *TubeRecv, *TubeSend;				// Delivery tube of packets to PPP module
	THREAD *PPPThread;						// PPP module thread
	UINT64 NextSendEchoRequestTick;			// Time to send the next Echo Request
	UINT64 LastRecvTick;					// Tick when some data has received at the end
	bool FlushRecvTube;						// Flag whether to flush the reception tube
	UINT EstablishedCount;					// Number of session establishment
	PPP_SESSION *PPPSession;				// Underlying PPP Session
};


//// Function prototype
const PROTO_IMPL *SstpGetProtoImpl();
const PROTO_OPTION *SstpOptions();
const char *SstpName();
bool SstpInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname);
void SstpFree(void *param);
bool SstpProcessData(void *param, TCP_RAW_DATA *in, FIFO *out);

SSTP_SERVER *NewSstpServer(CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname);
void FreeSstpServer(SSTP_SERVER *s);
void SstpProcessInterrupt(SSTP_SERVER *s);
SSTP_PACKET *SstpParsePacket(UCHAR *data, UINT size);
LIST *SstpParseAttributeList(UCHAR *data, UINT size, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpParseAttribute(UCHAR *data, UINT size);
void SstpFreeAttribute(SSTP_ATTRIBUTE *a);
void SstpFreeAttributeList(LIST *o);
void SstpFreePacket(SSTP_PACKET *p);
BUF *SstpBuildPacket(SSTP_PACKET *p);
BUF *SstpBuildAttributeList(LIST *o, USHORT message_type);
BUF *SstpBuildAttribute(SSTP_ATTRIBUTE *a);
void SstpAbort(SSTP_SERVER *s);
void SstpDisconnect(SSTP_SERVER *s);
void SstpProcessPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessControlPacket(SSTP_SERVER *s, SSTP_PACKET *p);
void SstpProcessDataPacket(SSTP_SERVER *s, SSTP_PACKET *p);
SSTP_ATTRIBUTE *SstpFindAttribute(SSTP_PACKET *p, UCHAR attribute_id);
SSTP_ATTRIBUTE *SstpNewAttribute(UCHAR attribute_id, UCHAR *data, UINT data_size);
SSTP_ATTRIBUTE *SstpNewStatusInfoAttribute(UCHAR attrib_id, UINT status);
SSTP_ATTRIBUTE *SstpNewCryptoBindingRequestAttribute(UCHAR hash_protocol_bitmask, UCHAR *nonce_32bytes);
SSTP_PACKET *SstpNewDataPacket(UCHAR *data, UINT size);
SSTP_PACKET *SstpNewControlPacket(USHORT message_type);
SSTP_PACKET *SstpNewControlPacketWithAnAttribute(USHORT message_type, SSTP_ATTRIBUTE *a);
void SstpSendPacket(SSTP_SERVER *s, SSTP_PACKET *p);

#endif	// PROTO_SSTP_H
