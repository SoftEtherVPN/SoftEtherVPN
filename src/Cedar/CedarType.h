// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// CedarType.h
// List of types that Cedar using

#ifndef	CEDARTYPE_H
#define	CEDARTYPE_H


// ==============================================================
//   Remote Procedure Call
// ==============================================================

typedef struct RPC RPC;


// ==============================================================
//   Account
// ==============================================================

typedef struct POLICY_ITEM POLICY_ITEM;
typedef struct POLICY POLICY;
typedef struct USERGROUP USERGROUP;
typedef struct USER USER;
typedef struct AUTHPASSWORD AUTHPASSWORD;
typedef struct AUTHUSERCERT AUTHUSERCERT;
typedef struct AUTHROOTCERT AUTHROOTCERT;
typedef struct AUTHRADIUS AUTHRADIUS;
typedef struct AUTHNT AUTHNT;


// ==============================================================
//   RADIUS
// ==============================================================

typedef struct RADIUS_LOGIN_OPTION RADIUS_LOGIN_OPTION;
typedef struct RADIUS_PACKET RADIUS_PACKET;
typedef struct RADIUS_AVP RADIUS_AVP;
typedef struct EAP_CLIENT EAP_CLIENT;
typedef struct EAP_MESSAGE EAP_MESSAGE;
typedef struct EAP_MSCHAPV2_GENERAL EAP_MSCHAPV2_GENERAL;
typedef struct EAP_MSCHAPV2_CHALLENGE EAP_MSCHAPV2_CHALLENGE;
typedef struct EAP_MSCHAPV2_RESPONSE EAP_MSCHAPV2_RESPONSE;
typedef struct EAP_MSCHAPV2_SUCCESS_SERVER EAP_MSCHAPV2_SUCCESS_SERVER;
typedef struct EAP_MSCHAPV2_SUCCESS_CLIENT EAP_MSCHAPV2_SUCCESS_CLIENT;
typedef struct EAP_PEAP EAP_PEAP;


// ==============================================================
//   Listener
// ==============================================================

typedef struct DOS DOS;
typedef struct LISTENER LISTENER;
typedef struct TCP_ACCEPTED_PARAM TCP_ACCEPTED_PARAM;
typedef struct UDP_ENTRY UDP_ENTRY;
typedef struct DYNAMIC_LISTENER DYNAMIC_LISTENER;


// ==============================================================
//   Logging
// ==============================================================

typedef struct PACKET_LOG PACKET_LOG;
typedef struct HUB_LOG HUB_LOG;
typedef struct RECORD RECORD;
typedef struct LOG LOG;
typedef struct ERASER ERASER;
typedef struct SLOG SLOG;


// ==============================================================
//   Connection
// ==============================================================

typedef struct KEEP KEEP;
typedef struct SECURE_SIGN SECURE_SIGN;
typedef struct RC4_KEY_PAIR RC4_KEY_PAIR;
typedef struct CLIENT_OPTION CLIENT_OPTION;
typedef struct CLIENT_AUTH CLIENT_AUTH;
typedef struct TCPSOCK TCPSOCK;
typedef struct TCP TCP;
typedef struct UDP UDP;
typedef struct BLOCK BLOCK;
typedef struct CONNECTION CONNECTION;


// ==============================================================
//   Session
// ==============================================================

typedef struct NODE_INFO NODE_INFO;
typedef struct PACKET_ADAPTER PACKET_ADAPTER;
typedef struct SESSION SESSION;
typedef struct UI_PASSWORD_DLG UI_PASSWORD_DLG;
typedef struct UI_MSG_DLG UI_MSG_DLG;
typedef struct UI_NICINFO UI_NICINFO;
typedef struct UI_CONNECTERROR_DLG UI_CONNECTERROR_DLG;
typedef struct UI_CHECKCERT UI_CHECKCERT;


// ==============================================================
//   Hub
// ==============================================================

typedef struct SE_LINK SE_LINK;
typedef struct TEST_HISTORY TEST_HISTORY;
typedef struct SE_TEST SE_TEST;
typedef struct HUBDB HUBDB;
typedef struct TRAFFIC_LIMITER TRAFFIC_LIMITER;
typedef struct STORM STORM;
typedef struct HUB_PA HUB_PA;
typedef struct HUB_OPTION HUB_OPTION;
typedef struct MAC_TABLE_ENTRY MAC_TABLE_ENTRY;
typedef struct IP_TABLE_ENTRY IP_TABLE_ENTRY;
typedef struct LOOP_LIST LOOP_LIST;
typedef struct ACCESS ACCESS;
typedef struct TICKET TICKET;
typedef struct TRAFFIC_DIFF TRAFFIC_DIFF;
typedef struct HUB HUB;
typedef struct ADMIN_OPTION ADMIN_OPTION;
typedef struct CRL CRL;
typedef struct AC AC;
typedef struct USERLIST USERLIST;


// ==============================================================
//   Protocol
// ==============================================================

typedef struct CHECK_CERT_THREAD_PROC CHECK_CERT_THREAD_PROC;
typedef struct SECURE_SIGN_THREAD_PROC SECURE_SIGN_THREAD_PROC;
typedef struct RAND_CACHE RAND_CACHE;
typedef struct BLACK BLACK;
typedef struct SEND_SIGNATURE_PARAM SEND_SIGNATURE_PARAM;
typedef struct UPDATE_CLIENT UPDATE_CLIENT;
typedef struct UPDATE_CLIENT_SETTING UPDATE_CLIENT_SETTING;


// ==============================================================
//   Link
// ==============================================================

typedef struct LINK LINK;


// ==============================================================
//   Virtual
// ==============================================================

typedef struct ARP_ENTRY ARP_ENTRY;
typedef struct ARP_WAIT ARP_WAIT;
typedef struct IP_WAIT IP_WAIT;
typedef struct IP_PART IP_PART;
typedef struct IP_COMBINE IP_COMBINE;
typedef struct NAT_ENTRY NAT_ENTRY;
typedef struct TCP_OPTION TCP_OPTION;
typedef struct VH VH;
typedef struct VH_OPTION VH_OPTION;
typedef struct DHCP_LEASE DHCP_LEASE;
typedef struct NATIVE_NAT NATIVE_NAT;
typedef struct NATIVE_NAT_ENTRY NATIVE_NAT_ENTRY;
typedef struct DNS_PARSED_PACKET DNS_PARSED_PACKET;


// ==============================================================
//   WPC
// ==============================================================

typedef struct INTERNET_SETTING INTERNET_SETTING;
typedef struct URL_DATA URL_DATA;
typedef struct WPC_ENTRY WPC_ENTRY;
typedef struct WPC_PACKET WPC_PACKET;
typedef struct WPC_CONNECT WPC_CONNECT;

// ==============================================================
//   VLAN
// ==============================================================

typedef struct ROUTE_TRACKING ROUTE_TRACKING;
typedef struct VLAN VLAN;
typedef struct INSTANCE_LIST INSTANCE_LIST;
typedef struct VLAN_PARAM VLAN_PARAM;

#ifdef	OS_UNIX
typedef struct UNIX_VLAN_LIST UNIX_VLAN_LIST;
#endif	// OS_UNIX

// ==============================================================
//   Null LAN
// ==============================================================

typedef struct NULL_LAN NULL_LAN;


// ==============================================================
//   Bridge
// ==============================================================

typedef struct ETH ETH;
typedef struct BRIDGE BRIDGE;
typedef struct LOCALBRIDGE LOCALBRIDGE;


// ==============================================================
//   Layer-3 Switch
// ==============================================================

typedef struct L3IF L3IF;
typedef struct L3SW L3SW;
typedef struct L3TABLE L3TABLE;
typedef struct L3ARPENTRY L3ARPENTRY;
typedef struct L3ARPWAIT L3ARPWAIT;
typedef struct L3PACKET L3PACKET;


// ==============================================================
//   Client
// ==============================================================

typedef struct ACCOUNT ACCOUNT;
typedef struct CLIENT_CONFIG CLIENT_CONFIG;
typedef struct RPC_CLIENT_VERSION RPC_CLIENT_VERSION;
typedef struct RPC_CLIENT_PASSWORD RPC_CLIENT_PASSWORD;
typedef struct RPC_CLIENT_PASSWORD_SETTING RPC_CLIENT_PASSWORD_SETTING;
typedef struct RPC_CLIENT_ENUM_CA_ITEM RPC_CLIENT_ENUM_CA_ITEM;
typedef struct RPC_CLIENT_ENUM_CA RPC_CLIENT_ENUM_CA;
typedef struct RPC_CERT RPC_CERT;
typedef struct RPC_CLIENT_DELETE_CA RPC_CLIENT_DELETE_CA;
typedef struct RPC_GET_CA RPC_GET_CA;
typedef struct RPC_GET_ISSUER RPC_GET_ISSUER;
typedef struct RPC_CLIENT_ENUM_SECURE_ITEM RPC_CLIENT_ENUM_SECURE_ITEM;
typedef struct RPC_CLIENT_ENUM_SECURE RPC_CLIENT_ENUM_SECURE;
typedef struct RPC_USE_SECURE RPC_USE_SECURE;
typedef struct RPC_ENUM_OBJECT_IN_SECURE RPC_ENUM_OBJECT_IN_SECURE;
typedef struct RPC_CLIENT_CREATE_VLAN RPC_CLIENT_CREATE_VLAN;
typedef struct RPC_CLIENT_GET_VLAN RPC_CLIENT_GET_VLAN;
typedef struct RPC_CLIENT_SET_VLAN RPC_CLIENT_SET_VLAN;
typedef struct RPC_CLIENT_ENUM_VLAN_ITEM RPC_CLIENT_ENUM_VLAN_ITEM;
typedef struct RPC_CLIENT_ENUM_VLAN RPC_CLIENT_ENUM_VLAN;
typedef struct RPC_CLIENT_CREATE_ACCOUNT RPC_CLIENT_CREATE_ACCOUNT;
typedef struct RPC_CLIENT_ENUM_ACCOUNT_ITEM RPC_CLIENT_ENUM_ACCOUNT_ITEM;
typedef struct RPC_CLIENT_ENUM_ACCOUNT RPC_CLIENT_ENUM_ACCOUNT;
typedef struct RPC_CLIENT_DELETE_ACCOUNT RPC_CLIENT_DELETE_ACCOUNT;
typedef struct RPC_RENAME_ACCOUNT RPC_RENAME_ACCOUNT;
typedef struct RPC_CLIENT_GET_ACCOUNT RPC_CLIENT_GET_ACCOUNT;
typedef struct RPC_CLIENT_CONNECT RPC_CLIENT_CONNECT;
typedef struct RPC_CLIENT_GET_CONNECTION_STATUS RPC_CLIENT_GET_CONNECTION_STATUS;
typedef struct CLIENT_RPC_CONNECTION CLIENT_RPC_CONNECTION;
typedef struct CLIENT CLIENT;
typedef struct RPC_CLIENT_NOTIFY RPC_CLIENT_NOTIFY;
typedef struct REMOTE_CLIENT REMOTE_CLIENT;
typedef struct NOTIFY_CLIENT NOTIFY_CLIENT;
typedef struct UNIX_VLAN UNIX_VLAN;
typedef struct CM_SETTING CM_SETTING;


// ==============================================================
//   Server
// ==============================================================

typedef struct HUB_LIST HUB_LIST;
typedef struct FARM_TASK FARM_TASK;
typedef struct FARM_MEMBER FARM_MEMBER;
typedef struct FARM_CONTROLLER FARM_CONTROLLER;
typedef struct SERVER_LISTENER SERVER_LISTENER;
typedef struct SERVER SERVER;
typedef struct RPC_ENUM_SESSION RPC_ENUM_SESSION;
typedef struct RPC_SESSION_STATUS RPC_SESSION_STATUS;
typedef struct CAPS CAPS;
typedef struct CAPSLIST CAPSLIST;
typedef struct LOG_FILE LOG_FILE;
typedef struct SYSLOG_SETTING SYSLOG_SETTING;
typedef struct HUB_SNAPSHOT HUB_SNAPSHOT;
typedef struct SERVER_SNAPSHOT SERVER_SNAPSHOT;
typedef struct SERVER_HUB_CREATE_HISTORY SERVER_HUB_CREATE_HISTORY;
typedef struct OPENVPN_SSTP_CONFIG OPENVPN_SSTP_CONFIG;

// ==============================================================
//   Server Admin Tool
// ==============================================================

typedef struct ADMIN ADMIN;
typedef struct RPC_TEST RPC_TEST;
typedef struct RPC_SERVER_INFO RPC_SERVER_INFO;
typedef struct RPC_SERVER_STATUS RPC_SERVER_STATUS;
typedef struct RPC_LISTENER RPC_LISTENER;
typedef struct RPC_LISTENER_LIST RPC_LISTENER_LIST;
typedef struct RPC_PORTS RPC_PORTS;
typedef struct RPC_STR RPC_STR;
typedef struct RPC_PROTO_OPTIONS RPC_PROTO_OPTIONS;
typedef struct RPC_SET_PASSWORD RPC_SET_PASSWORD;
typedef struct RPC_FARM RPC_FARM;
typedef struct RPC_FARM_HUB RPC_FARM_HUB;
typedef struct RPC_FARM_INFO RPC_FARM_INFO;
typedef struct RPC_ENUM_FARM_ITEM RPC_ENUM_FARM_ITEM;
typedef struct RPC_ENUM_FARM RPC_ENUM_FARM;
typedef struct RPC_FARM_CONNECTION_STATUS RPC_FARM_CONNECTION_STATUS;
typedef struct RPC_KEY_PAIR RPC_KEY_PAIR;
typedef struct RPC_HUB_OPTION RPC_HUB_OPTION;
typedef struct RPC_RADIUS RPC_RADIUS;
typedef struct RPC_HUB RPC_HUB;
typedef struct RPC_CREATE_HUB RPC_CREATE_HUB;
typedef struct RPC_ENUM_HUB_ITEM RPC_ENUM_HUB_ITEM;
typedef struct RPC_ENUM_HUB RPC_ENUM_HUB;
typedef struct RPC_DELETE_HUB RPC_DELETE_HUB;
typedef struct RPC_ENUM_CONNECTION_ITEM RPC_ENUM_CONNECTION_ITEM;
typedef struct RPC_ENUM_CONNECTION RPC_ENUM_CONNECTION;
typedef struct RPC_DISCONNECT_CONNECTION RPC_DISCONNECT_CONNECTION;
typedef struct RPC_CONNECTION_INFO RPC_CONNECTION_INFO;
typedef struct RPC_SET_HUB_ONLINE RPC_SET_HUB_ONLINE;
typedef struct RPC_HUB_STATUS RPC_HUB_STATUS;
typedef struct RPC_HUB_LOG RPC_HUB_LOG;
typedef struct RPC_HUB_ADD_CA RPC_HUB_ADD_CA;
typedef struct RPC_HUB_ENUM_CA_ITEM RPC_HUB_ENUM_CA_ITEM;
typedef struct RPC_HUB_ENUM_CA RPC_HUB_ENUM_CA;
typedef struct RPC_HUB_GET_CA RPC_HUB_GET_CA;
typedef struct RPC_HUB_DELETE_CA RPC_HUB_DELETE_CA;
typedef struct RPC_CREATE_LINK RPC_CREATE_LINK;
typedef struct RPC_ENUM_LINK_ITEM RPC_ENUM_LINK_ITEM;
typedef struct RPC_ENUM_LINK RPC_ENUM_LINK;
typedef struct RPC_LINK_STATUS RPC_LINK_STATUS;
typedef struct RPC_LINK RPC_LINK;
typedef struct RPC_ENUM_ACCESS_LIST RPC_ENUM_ACCESS_LIST;
typedef struct RPC_ADD_ACCESS RPC_ADD_ACCESS;
typedef struct RPC_DELETE_ACCESS RPC_DELETE_ACCESS;
typedef struct RPC_SET_USER RPC_SET_USER;
typedef struct RPC_ENUM_USER_ITEM RPC_ENUM_USER_ITEM;
typedef struct RPC_ENUM_USER RPC_ENUM_USER;
typedef struct RPC_SET_GROUP RPC_SET_GROUP;
typedef struct RPC_ENUM_GROUP_ITEM RPC_ENUM_GROUP_ITEM;
typedef struct RPC_ENUM_GROUP RPC_ENUM_GROUP;
typedef struct RPC_DELETE_USER RPC_DELETE_USER;
typedef struct RPC_ENUM_SESSION_ITEM RPC_ENUM_SESSION_ITEM;
typedef struct RPC_DELETE_SESSION RPC_DELETE_SESSION;
typedef struct RPC_ENUM_MAC_TABLE_ITEM RPC_ENUM_MAC_TABLE_ITEM;
typedef struct RPC_ENUM_MAC_TABLE RPC_ENUM_MAC_TABLE;
typedef struct RPC_ENUM_IP_TABLE_ITEM RPC_ENUM_IP_TABLE_ITEM;
typedef struct RPC_ENUM_IP_TABLE RPC_ENUM_IP_TABLE;
typedef struct RPC_DELETE_TABLE RPC_DELETE_TABLE;
typedef struct RPC_KEEP RPC_KEEP;
typedef struct RPC_ENUM_ETH_ITEM RPC_ENUM_ETH_ITEM;
typedef struct RPC_ENUM_ETH RPC_ENUM_ETH;
typedef struct RPC_LOCALBRIDGE RPC_LOCALBRIDGE;
typedef struct RPC_ENUM_LOCALBRIDGE RPC_ENUM_LOCALBRIDGE;
typedef struct RPC_BRIDGE_SUPPORT RPC_BRIDGE_SUPPORT;
typedef struct RPC_CONFIG RPC_CONFIG;
typedef struct RPC_ADMIN_OPTION RPC_ADMIN_OPTION;
typedef struct RPC_L3SW RPC_L3SW;
typedef struct RPC_L3IF RPC_L3IF;
typedef struct RPC_L3TABLE RPC_L3TABLE;
typedef struct RPC_ENUM_L3SW_ITEM RPC_ENUM_L3SW_ITEM;
typedef struct RPC_ENUM_L3SW RPC_ENUM_L3SW;
typedef struct RPC_ENUM_L3IF RPC_ENUM_L3IF;
typedef struct RPC_ENUM_L3TABLE RPC_ENUM_L3TABLE;
typedef struct RPC_CRL RPC_CRL;
typedef struct RPC_ENUM_CRL_ITEM RPC_ENUM_CRL_ITEM;
typedef struct RPC_ENUM_CRL RPC_ENUM_CRL;
typedef struct RPC_INT RPC_INT;
typedef struct RPC_AC_LIST RPC_AC_LIST;
typedef struct RPC_ENUM_LOG_FILE_ITEM RPC_ENUM_LOG_FILE_ITEM;
typedef struct RPC_ENUM_LOG_FILE RPC_ENUM_LOG_FILE;
typedef struct RPC_READ_LOG_FILE RPC_READ_LOG_FILE;
typedef struct DOWNLOAD_PROGRESS DOWNLOAD_PROGRESS;
typedef struct RPC_RENAME_LINK RPC_RENAME_LINK;
typedef struct RPC_ENUM_LICENSE_KEY RPC_ENUM_LICENSE_KEY;
typedef struct RPC_ENUM_LICENSE_KEY_ITEM RPC_ENUM_LICENSE_KEY_ITEM;
typedef struct RPC_LICENSE_STATUS RPC_LICENSE_STATUS;
typedef struct RPC_ENUM_ETH_VLAN_ITEM RPC_ENUM_ETH_VLAN_ITEM;
typedef struct RPC_ENUM_ETH_VLAN RPC_ENUM_ETH_VLAN;
typedef struct RPC_MSG RPC_MSG;
typedef struct RPC_WINVER RPC_WINVER;
typedef struct RPC_ENUM_ETHERIP_ID RPC_ENUM_ETHERIP_ID;
typedef struct RPC_SPECIAL_LISTENER RPC_SPECIAL_LISTENER;
typedef struct RPC_AZURE_STATUS RPC_AZURE_STATUS;


// ==============================================================
//  NAT
// ==============================================================

typedef struct NAT NAT;
typedef struct NAT_ADMIN NAT_ADMIN;
typedef struct RPC_DUMMY RPC_DUMMY;
typedef struct RPC_NAT_STATUS RPC_NAT_STATUS;
typedef struct RPC_NAT_INFO RPC_NAT_INFO;
typedef struct RPC_ENUM_NAT_ITEM RPC_ENUM_NAT_ITEM;
typedef struct RPC_ENUM_NAT RPC_ENUM_NAT;
typedef struct RPC_ENUM_DHCP_ITEM RPC_ENUM_DHCP_ITEM;
typedef struct RPC_ENUM_DHCP RPC_ENUM_DHCP;


// ==============================================================
//  SecureNAT
// ==============================================================

typedef struct SNAT SNAT;


// ==============================================================
//  WinUI
// ==============================================================

typedef struct LED LED;
typedef struct WIZARD WIZARD;
typedef struct WIZARD_PAGE WIZARD_PAGE;
typedef struct WINUI_UPDATE WINUI_UPDATE;
typedef struct WINUI_UPDATE_DLG_PARAM WINUI_UPDATE_DLG_PARAM;



// ==============================================================
//  Console
// ==============================================================

typedef struct PARAM PARAM;
typedef struct PARAM_VALUE PARAM_VALUE;
typedef struct CONSOLE CONSOLE;
typedef struct LOCAL_CONSOLE_PARAM LOCAL_CONSOLE_PARAM;
typedef struct CMD CMD;
typedef struct CMD_EVAL_MIN_MAX CMD_EVAL_MIN_MAX;


// ==============================================================
//  Command
// ==============================================================

typedef struct PS PS;
typedef struct PC PC;
typedef struct CT CT;
typedef struct CTC CTC;
typedef struct CTR CTR;
typedef struct TTC TTC;
typedef struct TTS TTS;
typedef struct TTS_WORKER TTS_WORKER;
typedef struct TTC_WORKER TTC_WORKER;
typedef struct TT_RESULT TT_RESULT;
typedef struct TTS_SOCK TTS_SOCK;
typedef struct TTC_SOCK TTC_SOCK;
typedef struct PT PT;

// ==============================================================
//  EtherLogger
// ==============================================================

typedef struct EL EL;
typedef struct EL_DEVICE EL_DEVICE;
typedef struct EL_LICENSE_STATUS EL_LICENSE_STATUS;
typedef struct RPC_ADD_DEVICE RPC_ADD_DEVICE;
typedef struct RPC_DELETE_DEVICE RPC_DELETE_DEVICE;
typedef struct RPC_ENUM_DEVICE_ITEM RPC_ENUM_DEVICE_ITEM;
typedef struct RPC_ENUM_DEVICE RPC_ENUM_DEVICE;
typedef struct RPC_EL_LICENSE_STATUS RPC_EL_LICENSE_STATUS;


// ==============================================================
//  Database
// ==============================================================

typedef struct LICENSE_PRODUCT LICENSE_PRODUCT;
typedef struct LICENSE_SYSTEM LICENSE_SYSTEM;
typedef struct LICENSE_DATA LICENSE_DATA;
typedef struct LICENSE LICENSE;
typedef struct LICENSE_STATUS LICENSE_STATUS;
typedef struct SECURE_PACK_FOLDER SECURE_PACK_FOLDER;
typedef struct WIDE_MACHINE_ID WIDE_MACHINE_ID;
typedef struct TRIAL_INFO TRIAL_INFO;


// ==============================================================
//  IPsec
// ==============================================================

typedef struct IPSEC_SERVER IPSEC_SERVER;
typedef struct IPSEC_SERVICES IPSEC_SERVICES;
typedef struct ETHERIP_ID ETHERIP_ID;


// ==============================================================
//  L2TP
// ==============================================================

typedef struct L2TP_SERVER L2TP_SERVER;
typedef struct L2TP_TUNNEL L2TP_TUNNEL;
typedef struct L2TP_SESSION L2TP_SESSION;
typedef struct L2TP_PACKET L2TP_PACKET;
typedef struct L2TP_AVP L2TP_AVP;
typedef struct L2TP_QUEUE L2TP_QUEUE;


// ==============================================================
//  PPP
// ==============================================================

typedef struct PPP_SESSION PPP_SESSION;
typedef struct PPP_OPTION PPP_OPTION;
typedef struct PPP_LCP PPP_LCP;
typedef struct PPP_PACKET PPP_PACKET;
typedef struct PPP_IPOPTION PPP_IPOPTION;
typedef struct PPP_IPV6OPTION PPP_IPV6OPTION;
typedef struct PPP_REQUEST_RESEND PPP_REQUEST_RESEND;
typedef struct PPP_DELAYED_PACKET PPP_DELAYED_PACKET;
typedef struct PPP_EAP PPP_EAP;
typedef struct PPP_EAP_TLS_CONTEXT PPP_EAP_TLS_CONTEXT;


// ==============================================================
//  EtherIP
// ==============================================================

typedef struct ETHERIP_SERVER ETHERIP_SERVER;


// ==============================================================
//  IKE
// ==============================================================

typedef struct IKE_SERVER IKE_SERVER;
typedef struct IKE_SA IKE_SA;
typedef struct IKE_SA_TRANSFORM_SETTING IKE_SA_TRANSFORM_SETTING;
typedef struct IKE_CLIENT IKE_CLIENT;
typedef struct IPSECSA IPSECSA;
typedef struct IKE_CAPS IKE_CAPS;

// ==============================================================
//  IPSec Packet
// ==============================================================

typedef struct IKE_COMMON_HEADER IKE_COMMON_HEADER;
typedef struct IKE_SA_HEADER IKE_SA_HEADER;
typedef struct IKE_PROPOSAL_HEADER IKE_PROPOSAL_HEADER;
typedef struct IKE_TRANSFORM_HEADER IKE_TRANSFORM_HEADER;
typedef struct IKE_TRANSFORM_VALUE IKE_TRANSFORM_VALUE;
typedef struct IKE_ID_HEADER IKE_ID_HEADER;
typedef struct IKE_CERT_HEADER IKE_CERT_HEADER;
typedef struct IKE_CERT_REQUEST_HEADER IKE_CERT_REQUEST_HEADER;
typedef struct IKE_NOTICE_HEADER IKE_NOTICE_HEADER;
typedef struct IKE_DELETE_HEADER IKE_DELETE_HEADER;
typedef struct IKE_NAT_OA_HEADER IKE_NAT_OA_HEADER;
typedef struct IPSEC_SA_TRANSFORM_SETTING IPSEC_SA_TRANSFORM_SETTING;

typedef struct IKE_PACKET_SA_PAYLOAD IKE_PACKET_SA_PAYLOAD;
typedef struct IKE_PACKET_PROPOSAL_PAYLOAD IKE_PACKET_PROPOSAL_PAYLOAD;
typedef struct IKE_PACKET_TRANSFORM_PAYLOAD IKE_PACKET_TRANSFORM_PAYLOAD;
typedef struct IKE_PACKET_TRANSFORM_VALUE IKE_PACKET_TRANSFORM_VALUE;
typedef struct IKE_PACKET_DATA_PAYLOAD IKE_PACKET_DATA_PAYLOAD;
typedef struct IKE_PACKET_ID_PAYLOAD IKE_PACKET_ID_PAYLOAD;
typedef struct IKE_PACKET_CERT_PAYLOAD IKE_PACKET_CERT_PAYLOAD;
typedef struct IKE_PACKET_CERT_REQUEST_PAYLOAD IKE_PACKET_CERT_REQUEST_PAYLOAD;
typedef struct IKE_PACKET_NOTICE_PAYLOAD IKE_PACKET_NOTICE_PAYLOAD;
typedef struct IKE_PACKET_DELETE_PAYLOAD IKE_PACKET_DELETE_PAYLOAD;
typedef struct IKE_PACKET_NAT_OA_PAYLOAD IKE_PACKET_NAT_OA_PAYLOAD;

typedef struct IKE_PACKET_PAYLOAD IKE_PACKET_PAYLOAD;
typedef struct IKE_PACKET IKE_PACKET;

typedef struct IKE_P1_KEYSET IKE_P1_KEYSET;

typedef struct IKE_CRYPTO IKE_CRYPTO;
typedef struct IKE_HASH IKE_HASH;
typedef struct IKE_DH IKE_DH;
typedef struct IKE_ENGINE IKE_ENGINE;
typedef struct IKE_CRYPTO_KEY IKE_CRYPTO_KEY;
typedef struct IKE_CRYPTO_PARAM IKE_CRYPTO_PARAM;


// ==============================================================
//  IPSec for Windows 7 / Vista / 2008 / 2008 R2
// ==============================================================

typedef struct IPSEC_WIN7 IPSEC_WIN7;


// ==============================================================
//  In-Process VPN Client
// ==============================================================

typedef struct IPC IPC;
typedef struct IPC_ARP IPC_ARP;
typedef struct IPC_ASYNC IPC_ASYNC;
typedef struct IPC_PARAM IPC_PARAM;
typedef struct IPC_DHCP_RELEASE_QUEUE IPC_DHCP_RELEASE_QUEUE;
typedef struct IPC_MSCHAP_V2_AUTHINFO IPC_MSCHAP_V2_AUTHINFO;
typedef struct IPC_SESSION_SHARED_BUFFER_DATA IPC_SESSION_SHARED_BUFFER_DATA;
typedef struct IPC_IPV6_ROUTER_ADVERTISEMENT IPC_IPV6_ROUTER_ADVERTISEMENT;
typedef struct IPC_DHCPV4_AWAIT IPC_DHCPV4_AWAIT;


// ==============================================================
//   UDP Acceleration
// ==============================================================

typedef struct UDP_ACCEL UDP_ACCEL;


// ==============================================================
//   SSTP (Microsoft Secure Socket Tunneling Protocol) Stack
// ==============================================================

typedef struct SSTP_SERVER SSTP_SERVER;
typedef struct SSTP_PACKET SSTP_PACKET;
typedef struct SSTP_ATTRIBUTE SSTP_ATTRIBUTE;


// ==============================================================
//   OpenVPN Protocol Stack
// ==============================================================

typedef struct OPENVPN_SERVER OPENVPN_SERVER;
typedef struct OPENVPN_SERVER_UDP OPENVPN_SERVER_UDP;
typedef struct OPENVPN_SESSION OPENVPN_SESSION;
typedef struct OPENVPN_CHANNEL OPENVPN_CHANNEL;
typedef struct OPENVPN_PACKET OPENVPN_PACKET;
typedef struct OPENVPN_CONTROL_PACKET OPENVPN_CONTROL_PACKET;
typedef struct OPENVPN_KEY_METHOD_2 OPENVPN_KEY_METHOD_2;


// ==============================================================
//   Dynamic DNS Client
// ==============================================================

typedef struct DDNS_CLIENT DDNS_CLIENT;
typedef struct DDNS_REGISTER_PARAM DDNS_REGISTER_PARAM;
typedef struct DDNS_CLIENT_STATUS DDNS_CLIENT_STATUS;


// ==============================================================
//   VPN Azure Client
// ==============================================================
typedef struct AZURE_CLIENT AZURE_CLIENT;
typedef struct AZURE_PARAM AZURE_PARAM;


// ==============================================================
//  VPN Gate Service
// ==============================================================

typedef struct VGS VGS;
typedef struct VGS_CONFIG VGS_CONFIG;
typedef struct VGC VGC;
typedef struct VGHOST VGHOST;
typedef struct VGHOSTLIST VGHOSTLIST;
typedef struct VGHOSTDAT VGHOSTDAT;
typedef struct VGCPOLLTASK VGCPOLLTASK;
typedef struct VGS_LOG VGS_LOG;
typedef struct VGC_UDPHOST VGC_UDPHOST;
typedef struct MIRROR_SERVER MIRROR_SERVER;


// ==============================================================
//   Native Stack
// ==============================================================

typedef struct NATIVE_STACK NATIVE_STACK;
typedef struct IPTABLES_STATE IPTABLES_STATE;
typedef struct IPTABLES_ENTRY IPTABLES_ENTRY;


// ==============================================================
//  SeLow User-mode
// ==============================================================

typedef struct SU SU;
typedef struct SU_ADAPTER SU_ADAPTER;
typedef struct SU_ADAPTER_LIST SU_ADAPTER_LIST;



#endif	// CEDARTYPE_H
