

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* Compiler settings for fwptypes.idl:
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


#ifndef __fwptypes_h__
#define __fwptypes_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "wtypes.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_fwptypes_0000_0000 */
/* [local] */ 

#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)
#endif
#ifdef __midl
typedef struct _LUID
    {
    DWORD LowPart;
    LONG HighPart;
    } 	LUID;

typedef struct _LUID *PLUID;

#endif
typedef /* [v1_enum] */ 
enum FWP_DIRECTION_
    {	FWP_DIRECTION_OUTBOUND	= 0,
	FWP_DIRECTION_INBOUND	= ( FWP_DIRECTION_OUTBOUND + 1 ) ,
	FWP_DIRECTION_MAX	= ( FWP_DIRECTION_INBOUND + 1 ) 
    } 	FWP_DIRECTION;

typedef /* [v1_enum] */ 
enum FWP_IP_VERSION_
    {	FWP_IP_VERSION_V4	= 0,
	FWP_IP_VERSION_V6	= ( FWP_IP_VERSION_V4 + 1 ) ,
	FWP_IP_VERSION_NONE	= ( FWP_IP_VERSION_V6 + 1 ) ,
	FWP_IP_VERSION_MAX	= ( FWP_IP_VERSION_NONE + 1 ) 
    } 	FWP_IP_VERSION;

typedef /* [v1_enum] */ 
enum FWP_NE_FAMILY_
    {	FWP_AF_INET	= FWP_IP_VERSION_V4,
	FWP_AF_INET6	= FWP_IP_VERSION_V6,
	FWP_AF_ETHER	= FWP_IP_VERSION_NONE,
	FWP_AF_NONE	= ( FWP_AF_ETHER + 1 ) 
    } 	FWP_AF;

typedef /* [v1_enum] */ 
enum FWP_ETHER_ENCAP_METHOD_
    {	FWP_ETHER_ENCAP_METHOD_ETHER_V2	= 0,
	FWP_ETHER_ENCAP_METHOD_SNAP	= 1,
	FWP_ETHER_ENCAP_METHOD_SNAP_W_OUI_ZERO	= 3
    } 	FWP_ETHER_ENCAP_METHOD;

typedef /* [v1_enum] */ 
enum FWP_DATA_TYPE_
    {	FWP_EMPTY	= 0,
	FWP_UINT8	= ( FWP_EMPTY + 1 ) ,
	FWP_UINT16	= ( FWP_UINT8 + 1 ) ,
	FWP_UINT32	= ( FWP_UINT16 + 1 ) ,
	FWP_UINT64	= ( FWP_UINT32 + 1 ) ,
	FWP_INT8	= ( FWP_UINT64 + 1 ) ,
	FWP_INT16	= ( FWP_INT8 + 1 ) ,
	FWP_INT32	= ( FWP_INT16 + 1 ) ,
	FWP_INT64	= ( FWP_INT32 + 1 ) ,
	FWP_FLOAT	= ( FWP_INT64 + 1 ) ,
	FWP_DOUBLE	= ( FWP_FLOAT + 1 ) ,
	FWP_BYTE_ARRAY16_TYPE	= ( FWP_DOUBLE + 1 ) ,
	FWP_BYTE_BLOB_TYPE	= ( FWP_BYTE_ARRAY16_TYPE + 1 ) ,
	FWP_SID	= ( FWP_BYTE_BLOB_TYPE + 1 ) ,
	FWP_SECURITY_DESCRIPTOR_TYPE	= ( FWP_SID + 1 ) ,
	FWP_TOKEN_INFORMATION_TYPE	= ( FWP_SECURITY_DESCRIPTOR_TYPE + 1 ) ,
	FWP_TOKEN_ACCESS_INFORMATION_TYPE	= ( FWP_TOKEN_INFORMATION_TYPE + 1 ) ,
	FWP_UNICODE_STRING_TYPE	= ( FWP_TOKEN_ACCESS_INFORMATION_TYPE + 1 ) ,
	FWP_BYTE_ARRAY6_TYPE	= ( FWP_UNICODE_STRING_TYPE + 1 ) ,
	FWP_SINGLE_DATA_TYPE_MAX	= 0xff,
	FWP_V4_ADDR_MASK	= ( FWP_SINGLE_DATA_TYPE_MAX + 1 ) ,
	FWP_V6_ADDR_MASK	= ( FWP_V4_ADDR_MASK + 1 ) ,
	FWP_RANGE_TYPE	= ( FWP_V6_ADDR_MASK + 1 ) ,
	FWP_DATA_TYPE_MAX	= ( FWP_RANGE_TYPE + 1 ) 
    } 	FWP_DATA_TYPE;

typedef struct FWP_BYTE_ARRAY6_
    {
    UINT8 byteArray6[ 6 ];
    } 	FWP_BYTE_ARRAY6;

#define FWP_BYTE_ARRAY6_SIZE 6
typedef struct FWP_BYTE_ARRAY16_
    {
    UINT8 byteArray16[ 16 ];
    } 	FWP_BYTE_ARRAY16;

typedef struct FWP_BYTE_BLOB_
    {
    UINT32 size;
    UINT8 *data;
    } 	FWP_BYTE_BLOB;

typedef struct FWP_TOKEN_INFORMATION_
    {
    ULONG sidCount;
    PSID_AND_ATTRIBUTES sids;
    ULONG restrictedSidCount;
    PSID_AND_ATTRIBUTES restrictedSids;
    } 	FWP_TOKEN_INFORMATION;

typedef struct FWP_VALUE0_
    {
    FWP_DATA_TYPE type;
    union 
        {
         /* Empty union arm */ 
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
        } 	;
    } 	FWP_VALUE0;

typedef /* [v1_enum] */ 
enum FWP_MATCH_TYPE_
    {	FWP_MATCH_EQUAL	= 0,
	FWP_MATCH_GREATER	= ( FWP_MATCH_EQUAL + 1 ) ,
	FWP_MATCH_LESS	= ( FWP_MATCH_GREATER + 1 ) ,
	FWP_MATCH_GREATER_OR_EQUAL	= ( FWP_MATCH_LESS + 1 ) ,
	FWP_MATCH_LESS_OR_EQUAL	= ( FWP_MATCH_GREATER_OR_EQUAL + 1 ) ,
	FWP_MATCH_RANGE	= ( FWP_MATCH_LESS_OR_EQUAL + 1 ) ,
	FWP_MATCH_FLAGS_ALL_SET	= ( FWP_MATCH_RANGE + 1 ) ,
	FWP_MATCH_FLAGS_ANY_SET	= ( FWP_MATCH_FLAGS_ALL_SET + 1 ) ,
	FWP_MATCH_FLAGS_NONE_SET	= ( FWP_MATCH_FLAGS_ANY_SET + 1 ) ,
	FWP_MATCH_EQUAL_CASE_INSENSITIVE	= ( FWP_MATCH_FLAGS_NONE_SET + 1 ) ,
	FWP_MATCH_NOT_EQUAL	= ( FWP_MATCH_EQUAL_CASE_INSENSITIVE + 1 ) ,
	FWP_MATCH_TYPE_MAX	= ( FWP_MATCH_NOT_EQUAL + 1 ) 
    } 	FWP_MATCH_TYPE;

typedef struct FWP_V4_ADDR_AND_MASK_
    {
    UINT32 addr;
    UINT32 mask;
    } 	FWP_V4_ADDR_AND_MASK;

#define FWP_V6_ADDR_SIZE (16)
typedef struct FWP_V6_ADDR_AND_MASK_
    {
    UINT8 addr[ 16 ];
    UINT8 prefixLength;
    } 	FWP_V6_ADDR_AND_MASK;

typedef struct FWP_RANGE0_
    {
    FWP_VALUE0 valueLow;
    FWP_VALUE0 valueHigh;
    } 	FWP_RANGE0;

#define FWP_ACTRL_MATCH_FILTER (0x00000001)

typedef struct FWP_CONDITION_VALUE0_
    {
    FWP_DATA_TYPE type;
    union 
        {
         /* Empty union arm */ 
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64 *uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64 *int64;
        float float32;
        double *double64;
        FWP_BYTE_ARRAY16 *byteArray16;
        FWP_BYTE_BLOB *byteBlob;
        SID *sid;
        FWP_BYTE_BLOB *sd;
        FWP_TOKEN_INFORMATION *tokenInformation;
        FWP_BYTE_BLOB *tokenAccessInformation;
        LPWSTR unicodeString;
        FWP_BYTE_ARRAY6 *byteArray6;
        FWP_V4_ADDR_AND_MASK *v4AddrMask;
        FWP_V6_ADDR_AND_MASK *v6AddrMask;
        FWP_RANGE0 *rangeValue;
        } 	;
    } 	FWP_CONDITION_VALUE0;

typedef /* [v1_enum] */ 
enum FWP_CLASSIFY_OPTION_TYPE_
    {	FWP_CLASSIFY_OPTION_MULTICAST_STATE	= 0,
	FWP_CLASSIFY_OPTION_LOOSE_SOURCE_MAPPING	= ( FWP_CLASSIFY_OPTION_MULTICAST_STATE + 1 ) ,
	FWP_CLASSIFY_OPTION_UNICAST_LIFETIME	= ( FWP_CLASSIFY_OPTION_LOOSE_SOURCE_MAPPING + 1 ) ,
	FWP_CLASSIFY_OPTION_MCAST_BCAST_LIFETIME	= ( FWP_CLASSIFY_OPTION_UNICAST_LIFETIME + 1 ) ,
	FWP_CLASSIFY_OPTION_SECURE_SOCKET_SECURITY_FLAGS	= ( FWP_CLASSIFY_OPTION_MCAST_BCAST_LIFETIME + 1 ) ,
	FWP_CLASSIFY_OPTION_SECURE_SOCKET_AUTHIP_MM_POLICY_KEY	= ( FWP_CLASSIFY_OPTION_SECURE_SOCKET_SECURITY_FLAGS + 1 ) ,
	FWP_CLASSIFY_OPTION_SECURE_SOCKET_AUTHIP_QM_POLICY_KEY	= ( FWP_CLASSIFY_OPTION_SECURE_SOCKET_AUTHIP_MM_POLICY_KEY + 1 ) ,
	FWP_CLASSIFY_OPTION_MAX	= ( FWP_CLASSIFY_OPTION_SECURE_SOCKET_AUTHIP_QM_POLICY_KEY + 1 ) 
    } 	FWP_CLASSIFY_OPTION_TYPE;

#define FWP_OPTION_VALUE_ALLOW_MULTICAST_STATE (0x00000000)
#define FWP_OPTION_VALUE_DENY_MULTICAST_STATE  (0x00000001)
#define FWP_OPTION_VALUE_ALLOW_GLOBAL_MULTICAST_STATE (0x00000002)
#define FWP_OPTION_VALUE_DISABLE_LOOSE_SOURCE (0x00000000)
#define FWP_OPTION_VALUE_ENABLE_LOOSE_SOURCE  (0x00000001)
#define FWP_ACTION_FLAG_TERMINATING     (0x00001000)
#define FWP_ACTION_FLAG_NON_TERMINATING (0x00002000)
#define FWP_ACTION_FLAG_CALLOUT         (0x00004000)
typedef UINT32 FWP_ACTION_TYPE;

#define FWP_ACTION_BLOCK \
   (0x00000001 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_PERMIT \
   (0x00000002 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_TERMINATING \
   (0x00000003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_INSPECTION \
   (0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_CALLOUT_UNKNOWN \
   (0x00000005 | FWP_ACTION_FLAG_CALLOUT)
#define FWP_ACTION_CONTINUE \
   (0x00000006 | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_NONE \
   (0x00000007)
#define FWP_ACTION_NONE_NO_MATCH \
   (0x00000008)
#define FWP_CONDITION_FLAG_IS_LOOPBACK              (0x00000001)
#define FWP_CONDITION_FLAG_IS_IPSEC_SECURED         (0x00000002)
#define FWP_CONDITION_FLAG_IS_REAUTHORIZE           (0x00000004)
#define FWP_CONDITION_FLAG_IS_WILDCARD_BIND         (0x00000008)
#define FWP_CONDITION_FLAG_IS_RAW_ENDPOINT          (0x00000010)
#define FWP_CONDITION_FLAG_IS_FRAGMENT              (0x00000020)
#define FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP        (0x00000040)
#define FWP_CONDITION_FLAG_IS_IPSEC_NATT_RECLASSIFY (0x00000080)
#define FWP_CONDITION_FLAG_REQUIRES_ALE_CLASSIFY    (0x00000100)
#define FWP_CONDITION_FLAG_IS_IMPLICIT_BIND         (0x00000200)
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
#define FWP_CONDITION_FLAG_IS_REASSEMBLED           (0x00000400)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWP_CONDITION_FLAG_IS_NAME_APP_SPECIFIED    (0x00004000)
#define FWP_CONDITION_FLAG_IS_PROMISCUOUS           (0x00008000)
#define FWP_CONDITION_FLAG_IS_AUTH_FW               (0x00010000)
#define FWP_CONDITION_FLAG_IS_RECLASSIFY            (0x00020000)
#define FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU    (0x00040000)
#define FWP_CONDITION_FLAG_IS_INBOUND_PASS_THRU     (0x00080000)
#define FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED (0x00100000)
#define FWP_CONDITION_REAUTHORIZE_REASON_POLICY_CHANGE             (0x00000001)
#define FWP_CONDITION_REAUTHORIZE_REASON_NEW_ARRIVAL_INTERFACE     (0x00000002)
#define FWP_CONDITION_REAUTHORIZE_REASON_NEW_NEXTHOP_INTERFACE     (0x00000004)
#define FWP_CONDITION_REAUTHORIZE_REASON_PROFILE_CROSSING          (0x00000008)
#define FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION       (0x00000010)
#define FWP_CONDITION_REAUTHORIZE_REASON_IPSEC_PROPERTIES_CHANGED  (0x00000020)
#define FWP_CONDITION_REAUTHORIZE_REASON_MID_STREAM_INSPECTION     (0x00000040)
#define FWP_CONDITION_REAUTHORIZE_REASON_SOCKET_PROPERTY_CHANGED   (0x00000080)
#define FWP_CONDITION_REAUTHORIZE_REASON_NEW_INBOUND_MCAST_BCAST_PACKET   (0x00000100)
#define FWP_CONDITION_SOCKET_PROPERTY_FLAG_IS_SYSTEM_PORT_RPC      (0x00000001)
#define FWP_CONDITION_SOCKET_PROPERTY_FLAG_ALLOW_EDGE_TRAFFIC      (0x00000002)
#define FWP_CONDITION_SOCKET_PROPERTY_FLAG_DENY_EDGE_TRAFFIC       (0x00000004)
#endif
#endif
typedef /* [v1_enum] */ 
enum FWP_FILTER_ENUM_TYPE_
    {	FWP_FILTER_ENUM_FULLY_CONTAINED	= 0,
	FWP_FILTER_ENUM_OVERLAPPING	= ( FWP_FILTER_ENUM_FULLY_CONTAINED + 1 ) ,
	FWP_FILTER_ENUM_TYPE_MAX	= ( FWP_FILTER_ENUM_OVERLAPPING + 1 ) 
    } 	FWP_FILTER_ENUM_TYPE;

#define FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH (0x00000001)
#define FWP_FILTER_ENUM_FLAG_SORTED                 (0x00000002)
#define FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY          (0x00000004)
#define FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME       (0x00000008)
#define FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED       (0x00000010)
#define FWP_FILTER_ENUM_VALID_FLAGS \
   (FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH | \
    FWP_FILTER_ENUM_FLAG_SORTED)
#define FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW        	(0x00000001)
#define FWP_CALLOUT_FLAG_ALLOW_OFFLOAD          		(0x00000002)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWP_CALLOUT_FLAG_ENABLE_COMMIT_ADD_NOTIFY    (0x00000004)
#define FWP_CALLOUT_FLAG_ALLOW_MID_STREAM_INSPECTION (0x00000008)
#define FWP_CALLOUT_FLAG_ALLOW_RECLASSIFY            (0x00000010)
#endif
#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4201)
#endif
#endif


extern RPC_IF_HANDLE __MIDL_itf_fwptypes_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_fwptypes_0000_0000_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif



