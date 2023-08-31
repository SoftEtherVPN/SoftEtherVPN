

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* Compiler settings for fwpmtypes.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 7.00.0555 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

/* verify that the <rpcsal.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCSAL_H_VERSION__
#define __REQUIRED_RPCSAL_H_VERSION__ 100
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__


#ifndef __fwpmtypes_h__
#define __fwpmtypes_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "fixed_fwptypes.h"
#include "fixed_iketypes.h"
#include "fixed_ipsectypes.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_fwpmtypes_0000_0000 */
/* [local] */ 

#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)
#endif
#ifndef _DEFINE_DL_ADDRESS_TYPE_
#define _DEFINE_DL_ADDRESS_TYPE_
typedef /* [public][public][v1_enum] */ 
enum __MIDL___MIDL_itf_fwpmtypes_0000_0000_0001
    {	DlUnicast	= 0,
	DlMulticast	= ( DlUnicast + 1 ) ,
	DlBroadcast	= ( DlMulticast + 1 ) 
    } 	DL_ADDRESS_TYPE;

typedef /* [v1_enum] */ enum __MIDL___MIDL_itf_fwpmtypes_0000_0000_0001 *PDL_ADDRESS_TYPE;

#endif
typedef struct FWPM_DISPLAY_DATA0_
    {
    wchar_t *name;
    wchar_t *description;
    } 	FWPM_DISPLAY_DATA0;

typedef /* [v1_enum] */ 
enum FWPM_CHANGE_TYPE_
    {	FWPM_CHANGE_ADD	= 1,
	FWPM_CHANGE_DELETE	= ( FWPM_CHANGE_ADD + 1 ) ,
	FWPM_CHANGE_TYPE_MAX	= ( FWPM_CHANGE_DELETE + 1 ) 
    } 	FWPM_CHANGE_TYPE;

#define FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_ADD    (0x00000001)
#define FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE (0x00000002)
typedef 
enum FWPM_SERVICE_STATE_
    {	FWPM_SERVICE_STOPPED	= 0,
	FWPM_SERVICE_START_PENDING	= ( FWPM_SERVICE_STOPPED + 1 ) ,
	FWPM_SERVICE_STOP_PENDING	= ( FWPM_SERVICE_START_PENDING + 1 ) ,
	FWPM_SERVICE_RUNNING	= ( FWPM_SERVICE_STOP_PENDING + 1 ) ,
	FWPM_SERVICE_STATE_MAX	= ( FWPM_SERVICE_RUNNING + 1 ) 
    } 	FWPM_SERVICE_STATE;

#define FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST (0x00000001)
#define FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST (0x00000002)
typedef 
enum FWPM_ENGINE_OPTION_
    {	FWPM_ENGINE_COLLECT_NET_EVENTS	= 0,
	FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS	= ( FWPM_ENGINE_COLLECT_NET_EVENTS + 1 ) ,
	FWPM_ENGINE_NAME_CACHE	= ( FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS + 1 ) ,
	FWPM_ENGINE_OPTION_MAX	= ( FWPM_ENGINE_NAME_CACHE + 1 ) 
    } 	FWPM_ENGINE_OPTION;

#define FWPM_SESSION_FLAG_DYNAMIC (0x00000001)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_SESSION_FLAG_RESERVED (0x10000000)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_SESSION0_
    {
    GUID sessionKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    DWORD processId;
    SID *sid;
    wchar_t *username;
    BOOL kernelMode;
    } 	FWPM_SESSION0;

typedef struct FWPM_SESSION_ENUM_TEMPLATE0_
    {
    UINT64 reserved;
    } 	FWPM_SESSION_ENUM_TEMPLATE0;

#define FWPM_PROVIDER_FLAG_PERSISTENT  (0x00000001)
#define FWPM_PROVIDER_FLAG_DISABLED    (0x00000010)
typedef struct FWPM_PROVIDER0_
    {
    GUID providerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    FWP_BYTE_BLOB providerData;
    wchar_t *serviceName;
    } 	FWPM_PROVIDER0;

typedef struct FWPM_PROVIDER_ENUM_TEMPLATE0_
    {
    UINT64 reserved;
    } 	FWPM_PROVIDER_ENUM_TEMPLATE0;

typedef struct FWPM_PROVIDER_CHANGE0_
    {
    FWPM_CHANGE_TYPE changeType;
    GUID providerKey;
    } 	FWPM_PROVIDER_CHANGE0;

typedef struct FWPM_PROVIDER_SUBSCRIPTION0_
    {
    FWPM_PROVIDER_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_PROVIDER_SUBSCRIPTION0;

#define FWPM_PROVIDER_CONTEXT_FLAG_PERSISTENT  (0x00000001)
typedef struct FWPM_CLASSIFY_OPTION0_
    {
    FWP_CLASSIFY_OPTION_TYPE type;
    FWP_VALUE0 value;
    } 	FWPM_CLASSIFY_OPTION0;

typedef struct FWPM_CLASSIFY_OPTIONS0_
    {
    UINT32 numOptions;
    FWPM_CLASSIFY_OPTION0 *options;
    } 	FWPM_CLASSIFY_OPTIONS0;

typedef /* [v1_enum] */ 
enum FWPM_PROVIDER_CONTEXT_TYPE_
    {	FWPM_IPSEC_KEYING_CONTEXT	= 0,
	FWPM_IPSEC_IKE_QM_TRANSPORT_CONTEXT	= ( FWPM_IPSEC_KEYING_CONTEXT + 1 ) ,
	FWPM_IPSEC_IKE_QM_TUNNEL_CONTEXT	= ( FWPM_IPSEC_IKE_QM_TRANSPORT_CONTEXT + 1 ) ,
	FWPM_IPSEC_AUTHIP_QM_TRANSPORT_CONTEXT	= ( FWPM_IPSEC_IKE_QM_TUNNEL_CONTEXT + 1 ) ,
	FWPM_IPSEC_AUTHIP_QM_TUNNEL_CONTEXT	= ( FWPM_IPSEC_AUTHIP_QM_TRANSPORT_CONTEXT + 1 ) ,
	FWPM_IPSEC_IKE_MM_CONTEXT	= ( FWPM_IPSEC_AUTHIP_QM_TUNNEL_CONTEXT + 1 ) ,
	FWPM_IPSEC_AUTHIP_MM_CONTEXT	= ( FWPM_IPSEC_IKE_MM_CONTEXT + 1 ) ,
	FWPM_CLASSIFY_OPTIONS_CONTEXT	= ( FWPM_IPSEC_AUTHIP_MM_CONTEXT + 1 ) ,
	FWPM_GENERAL_CONTEXT	= ( FWPM_CLASSIFY_OPTIONS_CONTEXT + 1 ) ,
	FWPM_IPSEC_IKEV2_QM_TUNNEL_CONTEXT	= ( FWPM_GENERAL_CONTEXT + 1 ) ,
	FWPM_IPSEC_IKEV2_MM_CONTEXT	= ( FWPM_IPSEC_IKEV2_QM_TUNNEL_CONTEXT + 1 ) ,
	FWPM_IPSEC_DOSP_CONTEXT	= ( FWPM_IPSEC_IKEV2_MM_CONTEXT + 1 ) ,
	FWPM_PROVIDER_CONTEXT_TYPE_MAX	= ( FWPM_IPSEC_DOSP_CONTEXT + 1 ) 
    } 	FWPM_PROVIDER_CONTEXT_TYPE;

typedef struct FWPM_PROVIDER_CONTEXT0_
    {
    GUID providerContextKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    FWPM_PROVIDER_CONTEXT_TYPE type;
    union 
        {
        IPSEC_KEYING_POLICY0 *keyingPolicy;
        IPSEC_TRANSPORT_POLICY0 *ikeQmTransportPolicy;
        IPSEC_TUNNEL_POLICY0 *ikeQmTunnelPolicy;
        IPSEC_TRANSPORT_POLICY0 *authipQmTransportPolicy;
        IPSEC_TUNNEL_POLICY0 *authipQmTunnelPolicy;
        IKEEXT_POLICY0 *ikeMmPolicy;
        IKEEXT_POLICY0 *authIpMmPolicy;
        FWP_BYTE_BLOB *dataBuffer;
        FWPM_CLASSIFY_OPTIONS0 *classifyOptions;
         /* Empty union arm */ 
        } 	;
    UINT64 providerContextId;
    } 	FWPM_PROVIDER_CONTEXT0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_PROVIDER_CONTEXT1_
    {
    GUID providerContextKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    FWPM_PROVIDER_CONTEXT_TYPE type;
    union 
        {
        IPSEC_KEYING_POLICY0 *keyingPolicy;
        IPSEC_TRANSPORT_POLICY1 *ikeQmTransportPolicy;
        IPSEC_TUNNEL_POLICY1 *ikeQmTunnelPolicy;
        IPSEC_TRANSPORT_POLICY1 *authipQmTransportPolicy;
        IPSEC_TUNNEL_POLICY1 *authipQmTunnelPolicy;
        IKEEXT_POLICY1 *ikeMmPolicy;
        IKEEXT_POLICY1 *authIpMmPolicy;
        FWP_BYTE_BLOB *dataBuffer;
        FWPM_CLASSIFY_OPTIONS0 *classifyOptions;
        IPSEC_TUNNEL_POLICY1 *ikeV2QmTunnelPolicy;
        IKEEXT_POLICY1 *ikeV2MmPolicy;
        IPSEC_DOSP_OPTIONS0 *idpOptions;
        } 	;
    UINT64 providerContextId;
    } 	FWPM_PROVIDER_CONTEXT1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0_
    {
    GUID *providerKey;
    FWPM_PROVIDER_CONTEXT_TYPE providerContextType;
    } 	FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0;

typedef struct FWPM_PROVIDER_CONTEXT_CHANGE0_
    {
    FWPM_CHANGE_TYPE changeType;
    GUID providerContextKey;
    UINT64 providerContextId;
    } 	FWPM_PROVIDER_CONTEXT_CHANGE0;

typedef struct FWPM_PROVIDER_CONTEXT_SUBSCRIPTION0_
    {
    FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_PROVIDER_CONTEXT_SUBSCRIPTION0;

#define FWPM_SUBLAYER_FLAG_PERSISTENT       (0x00000001)
typedef struct FWPM_SUBLAYER0_
    {
    GUID subLayerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    UINT16 weight;
    } 	FWPM_SUBLAYER0;

typedef struct FWPM_SUBLAYER_ENUM_TEMPLATE0_
    {
    GUID *providerKey;
    } 	FWPM_SUBLAYER_ENUM_TEMPLATE0;

typedef struct FWPM_SUBLAYER_CHANGE0_
    {
    FWPM_CHANGE_TYPE changeType;
    GUID subLayerKey;
    } 	FWPM_SUBLAYER_CHANGE0;

typedef struct FWPM_SUBLAYER_SUBSCRIPTION0_
    {
    FWPM_SUBLAYER_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_SUBLAYER_SUBSCRIPTION0;

#define FWPM_LAYER_FLAG_KERNEL           (0x00000001)
#define FWPM_LAYER_FLAG_BUILTIN          (0x00000002)
#define FWPM_LAYER_FLAG_CLASSIFY_MOSTLY  (0x00000004)
#define FWPM_LAYER_FLAG_BUFFERED         (0x00000008)
typedef /* [v1_enum] */ 
enum FWPM_FIELD_TYPE_
    {	FWPM_FIELD_RAW_DATA	= 0,
	FWPM_FIELD_IP_ADDRESS	= ( FWPM_FIELD_RAW_DATA + 1 ) ,
	FWPM_FIELD_FLAGS	= ( FWPM_FIELD_IP_ADDRESS + 1 ) ,
	FWPM_FIELD_TYPE_MAX	= ( FWPM_FIELD_FLAGS + 1 ) 
    } 	FWPM_FIELD_TYPE;

typedef struct FWPM_FIELD0_
    {
    GUID *fieldKey;
    FWPM_FIELD_TYPE type;
    FWP_DATA_TYPE dataType;
    } 	FWPM_FIELD0;

typedef struct FWPM_LAYER0_
    {
    GUID layerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 numFields;
    FWPM_FIELD0 *field;
    GUID defaultSubLayerKey;
    UINT16 layerId;
    } 	FWPM_LAYER0;

typedef struct FWPM_LAYER_ENUM_TEMPLATE0_
    {
    UINT64 reserved;
    } 	FWPM_LAYER_ENUM_TEMPLATE0;

#define FWPM_CALLOUT_FLAG_PERSISTENT             (0x00010000)
#define FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT  (0x00020000)
#define FWPM_CALLOUT_FLAG_REGISTERED             (0x00040000)
typedef struct FWPM_CALLOUT0_
    {
    GUID calloutKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    GUID applicableLayer;
    UINT32 calloutId;
    } 	FWPM_CALLOUT0;

typedef struct FWPM_CALLOUT_ENUM_TEMPLATE0_
    {
    GUID *providerKey;
    GUID layerKey;
    } 	FWPM_CALLOUT_ENUM_TEMPLATE0;

typedef struct FWPM_CALLOUT_CHANGE0_
    {
    FWPM_CHANGE_TYPE changeType;
    GUID calloutKey;
    UINT32 calloutId;
    } 	FWPM_CALLOUT_CHANGE0;

typedef struct FWPM_CALLOUT_SUBSCRIPTION0_
    {
    FWPM_CALLOUT_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_CALLOUT_SUBSCRIPTION0;

typedef struct FWPM_ACTION0_
    {
    FWP_ACTION_TYPE type;
    /* [switch_type] */ union 
        {
        GUID filterType;
        GUID calloutKey;
        } 	;
    } 	FWPM_ACTION0;

typedef struct FWPM_FILTER_CONDITION0_
    {
    GUID fieldKey;
    FWP_MATCH_TYPE matchType;
    FWP_CONDITION_VALUE0 conditionValue;
    } 	FWPM_FILTER_CONDITION0;

#define FWPM_FILTER_FLAG_NONE (0x00000000)
#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#define FWPM_FILTER_FLAG_BOOTTIME (0x00000002)
#define FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT  (0x00000004)
#define FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT (0x00000008)
#define FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED (0x00000010)
#define FWPM_FILTER_FLAG_DISABLED (0x00000020)
typedef struct FWPM_FILTER0_
    {
    GUID filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID *providerKey;
    FWP_BYTE_BLOB providerData;
    GUID layerKey;
    GUID subLayerKey;
    FWP_VALUE0 weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0 *filterCondition;
    FWPM_ACTION0 action;
    /* [switch_type] */ union 
        {
        UINT64 rawContext;
        GUID providerContextKey;
        } 	;
    GUID *reserved;
    UINT64 filterId;
    FWP_VALUE0 effectiveWeight;
    } 	FWPM_FILTER0;

typedef struct FWPM_FILTER_ENUM_TEMPLATE0_
    {
    GUID *providerKey;
    GUID layerKey;
    FWP_FILTER_ENUM_TYPE enumType;
    UINT32 flags;
    FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0 *providerContextTemplate;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0 *filterCondition;
    UINT32 actionMask;
    GUID *calloutKey;
    } 	FWPM_FILTER_ENUM_TEMPLATE0;

typedef struct FWPM_FILTER_CHANGE0_
    {
    FWPM_CHANGE_TYPE changeType;
    GUID filterKey;
    UINT64 filterId;
    } 	FWPM_FILTER_CHANGE0;

typedef struct FWPM_FILTER_SUBSCRIPTION0_
    {
    FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_FILTER_SUBSCRIPTION0;

typedef struct FWPM_LAYER_STATISTICS0_
    {
    GUID layerId;
    UINT32 classifyPermitCount;
    UINT32 classifyBlockCount;
    UINT32 classifyVetoCount;
    UINT32 numCacheEntries;
    } 	FWPM_LAYER_STATISTICS0;

typedef struct FWPM_STATISTICS0_
    {
    UINT32 numLayerStatistics;
    FWPM_LAYER_STATISTICS0 *layerStatistics;
    UINT32 inboundAllowedConnectionsV4;
    UINT32 inboundBlockedConnectionsV4;
    UINT32 outboundAllowedConnectionsV4;
    UINT32 outboundBlockedConnectionsV4;
    UINT32 inboundAllowedConnectionsV6;
    UINT32 inboundBlockedConnectionsV6;
    UINT32 outboundAllowedConnectionsV6;
    UINT32 outboundBlockedConnectionsV6;
    UINT32 inboundActiveConnectionsV4;
    UINT32 outboundActiveConnectionsV4;
    UINT32 inboundActiveConnectionsV6;
    UINT32 outboundActiveConnectionsV6;
    } 	FWPM_STATISTICS0;

#define FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET (0x00000001)
#define FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET  (0x00000002)
#define FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET (0x00000004)
#define FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET  (0x00000008)
#define FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET (0x00000010)
#define FWPM_NET_EVENT_FLAG_APP_ID_SET      (0x00000020)
#define FWPM_NET_EVENT_FLAG_USER_ID_SET     (0x00000040)
#define FWPM_NET_EVENT_FLAG_SCOPE_ID_SET    (0x00000080)
#define FWPM_NET_EVENT_FLAG_IP_VERSION_SET  (0x00000100)
#define FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET (0x00000200)
typedef struct FWPM_NET_EVENT_HEADER0_
    {
    FILETIME timeStamp;
    UINT32 flags;
    FWP_IP_VERSION ipVersion;
    UINT8 ipProtocol;
    union 
        {
        UINT32 localAddrV4;
        FWP_BYTE_ARRAY16 localAddrV6;
        } 	;
    union 
        {
        UINT32 remoteAddrV4;
        FWP_BYTE_ARRAY16 remoteAddrV6;
        } 	;
    UINT16 localPort;
    UINT16 remotePort;
    UINT32 scopeId;
    FWP_BYTE_BLOB appId;
    SID *userId;
    } 	FWPM_NET_EVENT_HEADER0;

typedef struct FWPM_NET_EVENT_HEADER1_
    {
    FILETIME timeStamp;
    UINT32 flags;
    FWP_IP_VERSION ipVersion;
    UINT8 ipProtocol;
    union 
        {
        UINT32 localAddrV4;
        FWP_BYTE_ARRAY16 localAddrV6;
         /* Empty union arm */ 
        } 	;
    union 
        {
        UINT32 remoteAddrV4;
        FWP_BYTE_ARRAY16 remoteAddrV6;
         /* Empty union arm */ 
        } 	;
    UINT16 localPort;
    UINT16 remotePort;
    UINT32 scopeId;
    FWP_BYTE_BLOB appId;
    SID *userId;
    union 
        {
        struct 
            {
            FWP_AF addressFamily;
            union 
                {
                struct 
                    {
                    FWP_BYTE_ARRAY6 dstAddrEth;
                    FWP_BYTE_ARRAY6 srcAddrEth;
                    DL_ADDRESS_TYPE addrType;
                    FWP_ETHER_ENCAP_METHOD encapMethod;
                    UINT16 etherType;
                    UINT32 snapControl;
                    UINT32 snapOui;
                    UINT16 vlanTag;
                    UINT64 ifLuid;
                    } 	;
                } 	;
            } 	;
         /* Empty union arm */ 
        } 	;
    } 	FWPM_NET_EVENT_HEADER1;

typedef /* [v1_enum] */ 
enum FWPM_NET_EVENT_TYPE_
    {	FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE	= 0,
	FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE	= ( FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE + 1 ) ,
	FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE	= ( FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE + 1 ) ,
	FWPM_NET_EVENT_TYPE_CLASSIFY_DROP	= ( FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE + 1 ) ,
	FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP	= ( FWPM_NET_EVENT_TYPE_CLASSIFY_DROP + 1 ) ,
	FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP	= ( FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP + 1 ) ,
	FWPM_NET_EVENT_TYPE_MAX	= ( FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP + 1 ) 
    } 	FWPM_NET_EVENT_TYPE;

#define IKEEXT_CERT_HASH_LEN 20
#define FWPM_NET_EVENT_IKEEXT_MM_FAILURE_FLAG_BENIGN (0x00000001)
#define FWPM_NET_EVENT_IKEEXT_MM_FAILURE_FLAG_MULTIPLE (0x00000002)
typedef struct FWPM_NET_EVENT_IKEEXT_MM_FAILURE0_
    {
    UINT32 failureErrorCode;
    IPSEC_FAILURE_POINT failurePoint;
    UINT32 flags;
    IKEEXT_KEY_MODULE_TYPE keyingModuleType;
    IKEEXT_MM_SA_STATE mmState;
    IKEEXT_SA_ROLE saRole;
    IKEEXT_AUTHENTICATION_METHOD_TYPE mmAuthMethod;
    UINT8 endCertHash[ 20 ];
    UINT64 mmId;
    UINT64 mmFilterId;
    } 	FWPM_NET_EVENT_IKEEXT_MM_FAILURE0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT_IKEEXT_MM_FAILURE1_
    {
    UINT32 failureErrorCode;
    IPSEC_FAILURE_POINT failurePoint;
    UINT32 flags;
    IKEEXT_KEY_MODULE_TYPE keyingModuleType;
    IKEEXT_MM_SA_STATE mmState;
    IKEEXT_SA_ROLE saRole;
    IKEEXT_AUTHENTICATION_METHOD_TYPE mmAuthMethod;
    UINT8 endCertHash[ 20 ];
    UINT64 mmId;
    UINT64 mmFilterId;
    wchar_t *localPrincipalNameForAuth;
    wchar_t *remotePrincipalNameForAuth;
    UINT32 numLocalPrincipalGroupSids;
    LPWSTR *localPrincipalGroupSids;
    UINT32 numRemotePrincipalGroupSids;
    LPWSTR *remotePrincipalGroupSids;
    } 	FWPM_NET_EVENT_IKEEXT_MM_FAILURE1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT_IKEEXT_QM_FAILURE0_
    {
    UINT32 failureErrorCode;
    IPSEC_FAILURE_POINT failurePoint;
    IKEEXT_KEY_MODULE_TYPE keyingModuleType;
    IKEEXT_QM_SA_STATE qmState;
    IKEEXT_SA_ROLE saRole;
    IPSEC_TRAFFIC_TYPE saTrafficType;
    union 
        {
         /* Empty union arm */ 
        FWP_CONDITION_VALUE0 localSubNet;
        } 	;
    union 
        {
         /* Empty union arm */ 
        FWP_CONDITION_VALUE0 remoteSubNet;
        } 	;
    UINT64 qmFilterId;
    } 	FWPM_NET_EVENT_IKEEXT_QM_FAILURE0;

#define FWPM_NET_EVENT_IKEEXT_EM_FAILURE_FLAG_MULTIPLE (0x00000001)
#define FWPM_NET_EVENT_IKEEXT_EM_FAILURE_FLAG_BENIGN (0x00000002)
typedef struct FWPM_NET_EVENT_IKEEXT_EM_FAILURE0_
    {
    UINT32 failureErrorCode;
    IPSEC_FAILURE_POINT failurePoint;
    UINT32 flags;
    IKEEXT_EM_SA_STATE emState;
    IKEEXT_SA_ROLE saRole;
    IKEEXT_AUTHENTICATION_METHOD_TYPE emAuthMethod;
    UINT8 endCertHash[ 20 ];
    UINT64 mmId;
    UINT64 qmFilterId;
    } 	FWPM_NET_EVENT_IKEEXT_EM_FAILURE0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT_IKEEXT_EM_FAILURE1_
    {
    UINT32 failureErrorCode;
    IPSEC_FAILURE_POINT failurePoint;
    UINT32 flags;
    IKEEXT_EM_SA_STATE emState;
    IKEEXT_SA_ROLE saRole;
    IKEEXT_AUTHENTICATION_METHOD_TYPE emAuthMethod;
    UINT8 endCertHash[ 20 ];
    UINT64 mmId;
    UINT64 qmFilterId;
    wchar_t *localPrincipalNameForAuth;
    wchar_t *remotePrincipalNameForAuth;
    UINT32 numLocalPrincipalGroupSids;
    LPWSTR *localPrincipalGroupSids;
    UINT32 numRemotePrincipalGroupSids;
    LPWSTR *remotePrincipalGroupSids;
    IPSEC_TRAFFIC_TYPE saTrafficType;
    } 	FWPM_NET_EVENT_IKEEXT_EM_FAILURE1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT_CLASSIFY_DROP0_
    {
    UINT64 filterId;
    UINT16 layerId;
    } 	FWPM_NET_EVENT_CLASSIFY_DROP0;

typedef struct FWPM_NET_EVENT_CLASSIFY_DROP1_
    {
    UINT64 filterId;
    UINT16 layerId;
    UINT32 reauthReason;
    UINT32 originalProfile;
    UINT32 currentProfile;
    UINT32 msFwpDirection;
    BOOL isLoopback;
    } 	FWPM_NET_EVENT_CLASSIFY_DROP1;

typedef struct FWPM_NET_EVENT_IPSEC_KERNEL_DROP0_
    {
    INT32 failureStatus;
    FWP_DIRECTION direction;
    IPSEC_SA_SPI spi;
    UINT64 filterId;
    UINT16 layerId;
    } 	FWPM_NET_EVENT_IPSEC_KERNEL_DROP0;

typedef struct FWPM_NET_EVENT_IPSEC_DOSP_DROP0_
    {
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 publicHostV4Addr;
        UINT8 publicHostV6Addr[ 16 ];
        } 	;
    union 
        {
        UINT32 internalHostV4Addr;
        UINT8 internalHostV6Addr[ 16 ];
        } 	;
    INT32 failureStatus;
    FWP_DIRECTION direction;
    } 	FWPM_NET_EVENT_IPSEC_DOSP_DROP0;

typedef struct FWPM_NET_EVENT0_
    {
    FWPM_NET_EVENT_HEADER0 header;
    FWPM_NET_EVENT_TYPE type;
    union 
        {
        FWPM_NET_EVENT_IKEEXT_MM_FAILURE0 *ikeMmFailure;
        FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure;
        FWPM_NET_EVENT_IKEEXT_EM_FAILURE0 *ikeEmFailure;
        FWPM_NET_EVENT_CLASSIFY_DROP0 *classifyDrop;
        FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;
        FWPM_NET_EVENT_IPSEC_DOSP_DROP0 *idpDrop;
        } 	;
    } 	FWPM_NET_EVENT0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT1_
    {
    FWPM_NET_EVENT_HEADER1 header;
    FWPM_NET_EVENT_TYPE type;
    union 
        {
        FWPM_NET_EVENT_IKEEXT_MM_FAILURE1 *ikeMmFailure;
        FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 *ikeQmFailure;
        FWPM_NET_EVENT_IKEEXT_EM_FAILURE1 *ikeEmFailure;
        FWPM_NET_EVENT_CLASSIFY_DROP1 *classifyDrop;
        FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 *ipsecDrop;
        FWPM_NET_EVENT_IPSEC_DOSP_DROP0 *idpDrop;
        } 	;
    } 	FWPM_NET_EVENT1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct FWPM_NET_EVENT_ENUM_TEMPLATE0_
    {
    FILETIME startTime;
    FILETIME endTime;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0 *filterCondition;
    } 	FWPM_NET_EVENT_ENUM_TEMPLATE0;

typedef struct FWPM_NET_EVENT_SUBSCRIPTION0_
    {
    FWPM_NET_EVENT_ENUM_TEMPLATE0 *enumTemplate;
    UINT32 flags;
    GUID sessionKey;
    } 	FWPM_NET_EVENT_SUBSCRIPTION0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef /* [v1_enum] */ 
enum FWPM_SYSTEM_PORT_TYPE_
    {	FWPM_SYSTEM_PORT_RPC_EPMAP	= 0,
	FWPM_SYSTEM_PORT_TEREDO	= ( FWPM_SYSTEM_PORT_RPC_EPMAP + 1 ) ,
	FWPM_SYSTEM_PORT_IPHTTPS_IN	= ( FWPM_SYSTEM_PORT_TEREDO + 1 ) ,
	FWPM_SYSTEM_PORT_IPHTTPS_OUT	= ( FWPM_SYSTEM_PORT_IPHTTPS_IN + 1 ) ,
	FWPM_SYSTEM_PORT_TYPE_MAX	= ( FWPM_SYSTEM_PORT_IPHTTPS_OUT + 1 ) 
    } 	FWPM_SYSTEM_PORT_TYPE;

typedef struct FWPM_SYSTEM_PORTS_BY_TYPE0_
    {
    FWPM_SYSTEM_PORT_TYPE type;
    UINT32 numPorts;
    UINT16 *ports;
    } 	FWPM_SYSTEM_PORTS_BY_TYPE0;

typedef struct FWPM_SYSTEM_PORTS0_
    {
    UINT32 numTypes;
    FWPM_SYSTEM_PORTS_BY_TYPE0 *types;
    } 	FWPM_SYSTEM_PORTS0;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4201)
#endif
#endif


extern RPC_IF_HANDLE __MIDL_itf_fwpmtypes_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_fwpmtypes_0000_0000_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif



