

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 7.00.0555 */
/* Compiler settings for ipsectypes.idl:
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


#ifndef __ipsectypes_h__
#define __ipsectypes_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "fixed_fwptypes.h"
#include "fixed_iketypes.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_ipsectypes_0000_0000 */
/* [local] */ 

#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)
#endif
typedef struct FWPM_FILTER0_ FWPM_FILTER0;

typedef struct IPSEC_SA_LIFETIME0_
    {
    UINT32 lifetimeSeconds;
    UINT32 lifetimeKilobytes;
    UINT32 lifetimePackets;
    } 	IPSEC_SA_LIFETIME0;

typedef /* [v1_enum] */ 
enum IPSEC_TRANSFORM_TYPE_
    {	IPSEC_TRANSFORM_AH	= 1,
	IPSEC_TRANSFORM_ESP_AUTH	= ( IPSEC_TRANSFORM_AH + 1 ) ,
	IPSEC_TRANSFORM_ESP_CIPHER	= ( IPSEC_TRANSFORM_ESP_AUTH + 1 ) ,
	IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER	= ( IPSEC_TRANSFORM_ESP_CIPHER + 1 ) ,
	IPSEC_TRANSFORM_ESP_AUTH_FW	= ( IPSEC_TRANSFORM_ESP_AUTH_AND_CIPHER + 1 ) ,
	IPSEC_TRANSFORM_TYPE_MAX	= ( IPSEC_TRANSFORM_ESP_AUTH_FW + 1 ) 
    } 	IPSEC_TRANSFORM_TYPE;

typedef /* [v1_enum] */ 
enum IPSEC_AUTH_TYPE_
    {	IPSEC_AUTH_MD5	= 0,
	IPSEC_AUTH_SHA_1	= ( IPSEC_AUTH_MD5 + 1 ) ,
	IPSEC_AUTH_SHA_256	= ( IPSEC_AUTH_SHA_1 + 1 ) ,
	IPSEC_AUTH_AES_128	= ( IPSEC_AUTH_SHA_256 + 1 ) ,
	IPSEC_AUTH_AES_192	= ( IPSEC_AUTH_AES_128 + 1 ) ,
	IPSEC_AUTH_AES_256	= ( IPSEC_AUTH_AES_192 + 1 ) ,
	IPSEC_AUTH_MAX	= ( IPSEC_AUTH_AES_256 + 1 ) 
    } 	IPSEC_AUTH_TYPE;

typedef UINT8 IPSEC_AUTH_CONFIG;

#define IPSEC_AUTH_CONFIG_HMAC_MD5_96         (0)
#define IPSEC_AUTH_CONFIG_HMAC_SHA_1_96       (1)
#define IPSEC_AUTH_CONFIG_HMAC_SHA_256_128    (2)
#define IPSEC_AUTH_CONFIG_GCM_AES_128         (3)
#define IPSEC_AUTH_CONFIG_GCM_AES_192         (4)
#define IPSEC_AUTH_CONFIG_GCM_AES_256         (5)
#define IPSEC_AUTH_CONFIG_MAX                 (6)
typedef struct IPSEC_AUTH_TRANSFORM_ID0_
    {
    IPSEC_AUTH_TYPE authType;
    IPSEC_AUTH_CONFIG authConfig;
    } 	IPSEC_AUTH_TRANSFORM_ID0;

typedef GUID IPSEC_CRYPTO_MODULE_ID;

typedef struct IPSEC_AUTH_TRANSFORM0_
    {
    IPSEC_AUTH_TRANSFORM_ID0 authTransformId;
    IPSEC_CRYPTO_MODULE_ID *cryptoModuleId;
    } 	IPSEC_AUTH_TRANSFORM0;

typedef /* [v1_enum] */ 
enum IPSEC_CIPHER_TYPE_
    {	IPSEC_CIPHER_TYPE_DES	= 1,
	IPSEC_CIPHER_TYPE_3DES	= ( IPSEC_CIPHER_TYPE_DES + 1 ) ,
	IPSEC_CIPHER_TYPE_AES_128	= ( IPSEC_CIPHER_TYPE_3DES + 1 ) ,
	IPSEC_CIPHER_TYPE_AES_192	= ( IPSEC_CIPHER_TYPE_AES_128 + 1 ) ,
	IPSEC_CIPHER_TYPE_AES_256	= ( IPSEC_CIPHER_TYPE_AES_192 + 1 ) ,
	IPSEC_CIPHER_TYPE_MAX	= ( IPSEC_CIPHER_TYPE_AES_256 + 1 ) 
    } 	IPSEC_CIPHER_TYPE;

typedef UINT8 IPSEC_CIPHER_CONFIG;

#define IPSEC_CIPHER_CONFIG_CBC_DES      (1)
#define IPSEC_CIPHER_CONFIG_CBC_3DES     (2)
#define IPSEC_CIPHER_CONFIG_CBC_AES_128  (3)
#define IPSEC_CIPHER_CONFIG_CBC_AES_192  (4)
#define IPSEC_CIPHER_CONFIG_CBC_AES_256  (5)
#define IPSEC_CIPHER_CONFIG_GCM_AES_128  (6)
#define IPSEC_CIPHER_CONFIG_GCM_AES_192  (7)
#define IPSEC_CIPHER_CONFIG_GCM_AES_256  (8)
#define IPSEC_CIPHER_CONFIG_MAX          (9)
typedef struct IPSEC_CIPHER_TRANSFORM_ID0_
    {
    IPSEC_CIPHER_TYPE cipherType;
    IPSEC_CIPHER_CONFIG cipherConfig;
    } 	IPSEC_CIPHER_TRANSFORM_ID0;

typedef struct IPSEC_CIPHER_TRANSFORM0_
    {
    IPSEC_CIPHER_TRANSFORM_ID0 cipherTransformId;
    IPSEC_CRYPTO_MODULE_ID *cryptoModuleId;
    } 	IPSEC_CIPHER_TRANSFORM0;

typedef struct IPSEC_AUTH_AND_CIPHER_TRANSFORM0_
    {
    IPSEC_AUTH_TRANSFORM0 authTransform;
    IPSEC_CIPHER_TRANSFORM0 cipherTransform;
    } 	IPSEC_AUTH_AND_CIPHER_TRANSFORM0;

typedef struct IPSEC_SA_TRANSFORM0_
    {
    IPSEC_TRANSFORM_TYPE ipsecTransformType;
    union 
        {
        IPSEC_AUTH_TRANSFORM0 *ahTransform;
        IPSEC_AUTH_TRANSFORM0 *espAuthTransform;
        IPSEC_CIPHER_TRANSFORM0 *espCipherTransform;
        IPSEC_AUTH_AND_CIPHER_TRANSFORM0 *espAuthAndCipherTransform;
        IPSEC_AUTH_TRANSFORM0 *espAuthFwTransform;
        } 	;
    } 	IPSEC_SA_TRANSFORM0;

#define espAuthTranform espAuthTransform
typedef /* [v1_enum] */ 
enum IPSEC_PFS_GROUP_
    {	IPSEC_PFS_NONE	= 0,
	IPSEC_PFS_1	= ( IPSEC_PFS_NONE + 1 ) ,
	IPSEC_PFS_2	= ( IPSEC_PFS_1 + 1 ) ,
	IPSEC_PFS_2048	= ( IPSEC_PFS_2 + 1 ) ,
	IPSEC_PFS_ECP_256	= ( IPSEC_PFS_2048 + 1 ) ,
	IPSEC_PFS_ECP_384	= ( IPSEC_PFS_ECP_256 + 1 ) ,
	IPSEC_PFS_MM	= ( IPSEC_PFS_ECP_384 + 1 ) ,
	IPSEC_PFS_MAX	= ( IPSEC_PFS_MM + 1 ) 
    } 	IPSEC_PFS_GROUP;

typedef struct IPSEC_PROPOSAL0_
    {
    IPSEC_SA_LIFETIME0 lifetime;
    UINT32 numSaTransforms;
    IPSEC_SA_TRANSFORM0 *saTransforms;
    IPSEC_PFS_GROUP pfsGroup;
    } 	IPSEC_PROPOSAL0;

typedef struct IPSEC_SA_IDLE_TIMEOUT0_
    {
    UINT32 idleTimeoutSeconds;
    UINT32 idleTimeoutSecondsFailOver;
    } 	IPSEC_SA_IDLE_TIMEOUT0;

#define IPSEC_POLICY_FLAG_ND_SECURE     (0x00000002)
#define IPSEC_POLICY_FLAG_ND_BOUNDARY   (0x00000004)
#define IPSEC_POLICY_FLAG_CLEAR_DF_ON_TUNNEL   (0x00000008)
#define IPSEC_POLICY_FLAG_NAT_ENCAP_ALLOW_PEER_BEHIND_NAT   (0x00000010)
#define IPSEC_POLICY_FLAG_NAT_ENCAP_ALLOW_GENERAL_NAT_TRAVERSAL   (0x00000020)
#define IPSEC_POLICY_FLAG_DONT_NEGOTIATE_SECOND_LIFETIME   (0x00000040)
#define IPSEC_POLICY_FLAG_DONT_NEGOTIATE_BYTE_LIFETIME   (0x00000080)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_POLICY_FLAG_ENABLE_V6_IN_V4_TUNNELING  (0x00000100)
#define IPSEC_POLICY_FLAG_ENABLE_SERVER_ADDR_ASSIGNMENT  (0x00000200)
#define IPSEC_POLICY_FLAG_TUNNEL_ALLOW_OUTBOUND_CLEAR_CONNECTION  (0x00000400)
#define IPSEC_POLICY_FLAG_TUNNEL_BYPASS_ALREADY_SECURE_CONNECTION (0x00000800)
#define IPSEC_POLICY_FLAG_TUNNEL_BYPASS_ICMPV6 (0x00001000)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TRANSPORT_POLICY0_
    {
    UINT32 numIpsecProposals;
    IPSEC_PROPOSAL0 *ipsecProposals;
    UINT32 flags;
    UINT32 ndAllowClearTimeoutSeconds;
    IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
    IKEEXT_EM_POLICY0 *emPolicy;
    } 	IPSEC_TRANSPORT_POLICY0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TRANSPORT_POLICY1_
    {
    UINT32 numIpsecProposals;
    IPSEC_PROPOSAL0 *ipsecProposals;
    UINT32 flags;
    UINT32 ndAllowClearTimeoutSeconds;
    IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
    IKEEXT_EM_POLICY1 *emPolicy;
    } 	IPSEC_TRANSPORT_POLICY1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TUNNEL_ENDPOINTS0_
    {
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 localV4Address;
        UINT8 localV6Address[ 16 ];
        } 	;
    union 
        {
        UINT32 remoteV4Address;
        UINT8 remoteV6Address[ 16 ];
        } 	;
    } 	IPSEC_TUNNEL_ENDPOINTS0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TUNNEL_ENDPOINTS1_
    {
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 localV4Address;
        UINT8 localV6Address[ 16 ];
        } 	;
    union 
        {
        UINT32 remoteV4Address;
        UINT8 remoteV6Address[ 16 ];
        } 	;
    UINT64 localIfLuid;
    } 	IPSEC_TUNNEL_ENDPOINTS1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TUNNEL_POLICY0_
    {
    UINT32 flags;
    UINT32 numIpsecProposals;
    IPSEC_PROPOSAL0 *ipsecProposals;
    IPSEC_TUNNEL_ENDPOINTS0 tunnelEndpoints;
    IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
    IKEEXT_EM_POLICY0 *emPolicy;
    } 	IPSEC_TUNNEL_POLICY0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TUNNEL_POLICY1_
    {
    UINT32 flags;
    UINT32 numIpsecProposals;
    IPSEC_PROPOSAL0 *ipsecProposals;
    IPSEC_TUNNEL_ENDPOINTS1 tunnelEndpoints;
    IPSEC_SA_IDLE_TIMEOUT0 saIdleTimeout;
    IKEEXT_EM_POLICY1 *emPolicy;
    } 	IPSEC_TUNNEL_POLICY1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_KEYING_POLICY0_
    {
    UINT32 numKeyMods;
    GUID *keyModKeys;
    } 	IPSEC_KEYING_POLICY0;

typedef struct IPSEC_AGGREGATE_SA_STATISTICS0_
    {
    UINT32 activeSas;
    UINT32 pendingSaNegotiations;
    UINT32 totalSasAdded;
    UINT32 totalSasDeleted;
    UINT32 successfulRekeys;
    UINT32 activeTunnels;
    UINT32 offloadedSas;
    } 	IPSEC_AGGREGATE_SA_STATISTICS0;

typedef struct IPSEC_ESP_DROP_PACKET_STATISTICS0_
    {
    UINT32 invalidSpisOnInbound;
    UINT32 decryptionFailuresOnInbound;
    UINT32 authenticationFailuresOnInbound;
    UINT32 replayCheckFailuresOnInbound;
    UINT32 saNotInitializedOnInbound;
    } 	IPSEC_ESP_DROP_PACKET_STATISTICS0;

typedef struct IPSEC_AH_DROP_PACKET_STATISTICS0_
    {
    UINT32 invalidSpisOnInbound;
    UINT32 authenticationFailuresOnInbound;
    UINT32 replayCheckFailuresOnInbound;
    UINT32 saNotInitializedOnInbound;
    } 	IPSEC_AH_DROP_PACKET_STATISTICS0;

typedef struct IPSEC_AGGREGATE_DROP_PACKET_STATISTICS0_
    {
    UINT32 invalidSpisOnInbound;
    UINT32 decryptionFailuresOnInbound;
    UINT32 authenticationFailuresOnInbound;
    UINT32 udpEspValidationFailuresOnInbound;
    UINT32 replayCheckFailuresOnInbound;
    UINT32 invalidClearTextInbound;
    UINT32 saNotInitializedOnInbound;
    UINT32 receiveOverIncorrectSaInbound;
    UINT32 secureReceivesNotMatchingFilters;
    } 	IPSEC_AGGREGATE_DROP_PACKET_STATISTICS0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_AGGREGATE_DROP_PACKET_STATISTICS1_
    {
    UINT32 invalidSpisOnInbound;
    UINT32 decryptionFailuresOnInbound;
    UINT32 authenticationFailuresOnInbound;
    UINT32 udpEspValidationFailuresOnInbound;
    UINT32 replayCheckFailuresOnInbound;
    UINT32 invalidClearTextInbound;
    UINT32 saNotInitializedOnInbound;
    UINT32 receiveOverIncorrectSaInbound;
    UINT32 secureReceivesNotMatchingFilters;
    UINT32 totalDropPacketsInbound;
    } 	IPSEC_AGGREGATE_DROP_PACKET_STATISTICS1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TRAFFIC_STATISTICS0_
    {
    UINT64 encryptedByteCount;
    UINT64 authenticatedAHByteCount;
    UINT64 authenticatedESPByteCount;
    UINT64 transportByteCount;
    UINT64 tunnelByteCount;
    UINT64 offloadByteCount;
    } 	IPSEC_TRAFFIC_STATISTICS0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TRAFFIC_STATISTICS1_
    {
    UINT64 encryptedByteCount;
    UINT64 authenticatedAHByteCount;
    UINT64 authenticatedESPByteCount;
    UINT64 transportByteCount;
    UINT64 tunnelByteCount;
    UINT64 offloadByteCount;
    UINT64 totalSuccessfulPackets;
    } 	IPSEC_TRAFFIC_STATISTICS1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_STATISTICS0_
    {
    IPSEC_AGGREGATE_SA_STATISTICS0 aggregateSaStatistics;
    IPSEC_ESP_DROP_PACKET_STATISTICS0 espDropPacketStatistics;
    IPSEC_AH_DROP_PACKET_STATISTICS0 ahDropPacketStatistics;
    IPSEC_AGGREGATE_DROP_PACKET_STATISTICS0 aggregateDropPacketStatistics;
    IPSEC_TRAFFIC_STATISTICS0 inboundTrafficStatistics;
    IPSEC_TRAFFIC_STATISTICS0 outboundTrafficStatistics;
    } 	IPSEC_STATISTICS0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_STATISTICS1_
    {
    IPSEC_AGGREGATE_SA_STATISTICS0 aggregateSaStatistics;
    IPSEC_ESP_DROP_PACKET_STATISTICS0 espDropPacketStatistics;
    IPSEC_AH_DROP_PACKET_STATISTICS0 ahDropPacketStatistics;
    IPSEC_AGGREGATE_DROP_PACKET_STATISTICS1 aggregateDropPacketStatistics;
    IPSEC_TRAFFIC_STATISTICS1 inboundTrafficStatistics;
    IPSEC_TRAFFIC_STATISTICS1 outboundTrafficStatistics;
    } 	IPSEC_STATISTICS1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef UINT32 IPSEC_SA_SPI;

typedef struct IPSEC_SA_AUTH_INFORMATION0_
    {
    IPSEC_AUTH_TRANSFORM0 authTransform;
    FWP_BYTE_BLOB authKey;
    } 	IPSEC_SA_AUTH_INFORMATION0;

typedef struct IPSEC_SA_CIPHER_INFORMATION0_
    {
    IPSEC_CIPHER_TRANSFORM0 cipherTransform;
    FWP_BYTE_BLOB cipherKey;
    } 	IPSEC_SA_CIPHER_INFORMATION0;

typedef struct IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0_
    {
    IPSEC_SA_CIPHER_INFORMATION0 saCipherInformation;
    IPSEC_SA_AUTH_INFORMATION0 saAuthInformation;
    } 	IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0;

typedef struct IPSEC_SA0_
    {
    IPSEC_SA_SPI spi;
    IPSEC_TRANSFORM_TYPE saTransformType;
    union 
        {
        IPSEC_SA_AUTH_INFORMATION0 *ahInformation;
        IPSEC_SA_AUTH_INFORMATION0 *espAuthInformation;
        IPSEC_SA_CIPHER_INFORMATION0 *espCipherInformation;
        IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0 *espAuthAndCipherInformation;
        IPSEC_SA_AUTH_INFORMATION0 *espAuthFwInformation;
        } 	;
    } 	IPSEC_SA0;

typedef struct IPSEC_KEYMODULE_STATE0_
    {
    GUID keyModuleKey;
    FWP_BYTE_BLOB stateBlob;
    } 	IPSEC_KEYMODULE_STATE0;

typedef UINT64 IPSEC_TOKEN_HANDLE;

typedef /* [v1_enum] */ 
enum IPSEC_TOKEN_TYPE_
    {	IPSEC_TOKEN_TYPE_MACHINE	= 0,
	IPSEC_TOKEN_TYPE_IMPERSONATION	= ( IPSEC_TOKEN_TYPE_MACHINE + 1 ) ,
	IPSEC_TOKEN_TYPE_MAX	= ( IPSEC_TOKEN_TYPE_IMPERSONATION + 1 ) 
    } 	IPSEC_TOKEN_TYPE;

typedef /* [v1_enum] */ 
enum IPSEC_TOKEN_PRINCIPAL_
    {	IPSEC_TOKEN_PRINCIPAL_LOCAL	= 0,
	IPSEC_TOKEN_PRINCIPAL_PEER	= ( IPSEC_TOKEN_PRINCIPAL_LOCAL + 1 ) ,
	IPSEC_TOKEN_PRINCIPAL_MAX	= ( IPSEC_TOKEN_PRINCIPAL_PEER + 1 ) 
    } 	IPSEC_TOKEN_PRINCIPAL;

typedef /* [v1_enum] */ 
enum IPSEC_TOKEN_MODE_
    {	IPSEC_TOKEN_MODE_MAIN	= 0,
	IPSEC_TOKEN_MODE_EXTENDED	= ( IPSEC_TOKEN_MODE_MAIN + 1 ) ,
	IPSEC_TOKEN_MODE_MAX	= ( IPSEC_TOKEN_MODE_EXTENDED + 1 ) 
    } 	IPSEC_TOKEN_MODE;

typedef struct IPSEC_TOKEN0_
    {
    IPSEC_TOKEN_TYPE type;
    IPSEC_TOKEN_PRINCIPAL principal;
    IPSEC_TOKEN_MODE mode;
    IPSEC_TOKEN_HANDLE token;
    } 	IPSEC_TOKEN0;

typedef struct IPSEC_ID0_
    {
    wchar_t *mmTargetName;
    wchar_t *emTargetName;
    UINT32 numTokens;
    IPSEC_TOKEN0 *tokens;
    UINT64 explicitCredentials;
    UINT64 logonId;
    } 	IPSEC_ID0;

#define IPSEC_SA_BUNDLE_FLAG_ND_SECURE (0x00000001)
#define IPSEC_SA_BUNDLE_FLAG_ND_BOUNDARY (0x00000002)
#define IPSEC_SA_BUNDLE_FLAG_ND_PEER_NAT_BOUNDARY (0x00000004)
#define IPSEC_SA_BUNDLE_FLAG_GUARANTEE_ENCRYPTION (0x00000008)
#define IPSEC_SA_BUNDLE_FLAG_NLB (0x00000010)
#define IPSEC_SA_BUNDLE_FLAG_NO_MACHINE_LUID_VERIFY (0x00000020)
#define IPSEC_SA_BUNDLE_FLAG_NO_IMPERSONATION_LUID_VERIFY (0x00000040)
#define IPSEC_SA_BUNDLE_FLAG_NO_EXPLICIT_CRED_MATCH (0x00000080)
#define IPSEC_SA_BUNDLE_FLAG_ALLOW_NULL_TARGET_NAME_MATCH (0x00000200)
#define IPSEC_SA_BUNDLE_FLAG_CLEAR_DF_ON_TUNNEL   (0x00000400)
#define IPSEC_SA_BUNDLE_FLAG_ASSUME_UDP_CONTEXT_OUTBOUND (0x00000800)
#if (NTDDI_VERSION >= NTDDI_WIN6SP1)
#define IPSEC_SA_BUNDLE_FLAG_ND_PEER_BOUNDARY (0x00001000)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_SA_BUNDLE_FLAG_SUPPRESS_DUPLICATE_DELETION (0x00002000)
#define IPSEC_SA_BUNDLE_FLAG_PEER_SUPPORTS_GUARANTEE_ENCRYPTION (0x00004000)
#define IPSEC_SA_BUNDLE_FLAG_FORCE_INBOUND_CONNECTIONS (0x00008000)
#define IPSEC_SA_BUNDLE_FLAG_FORCE_OUTBOUND_CONNECTIONS (0x00010000)
#define IPSEC_SA_BUNDLE_FLAG_FORWARD_PATH_INITIATOR (0x00020000)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_BUNDLE0_
    {
    UINT32 flags;
    IPSEC_SA_LIFETIME0 lifetime;
    UINT32 idleTimeoutSeconds;
    UINT32 ndAllowClearTimeoutSeconds;
    IPSEC_ID0 *ipsecId;
    UINT32 napContext;
    UINT32 qmSaId;
    UINT32 numSAs;
    IPSEC_SA0 *saList;
    IPSEC_KEYMODULE_STATE0 *keyModuleState;
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 peerV4PrivateAddress;
         /* Empty union arm */ 
        } 	;
    UINT64 mmSaId;
    IPSEC_PFS_GROUP pfsGroup;
    } 	IPSEC_SA_BUNDLE0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_BUNDLE1_
    {
    UINT32 flags;
    IPSEC_SA_LIFETIME0 lifetime;
    UINT32 idleTimeoutSeconds;
    UINT32 ndAllowClearTimeoutSeconds;
    IPSEC_ID0 *ipsecId;
    UINT32 napContext;
    UINT32 qmSaId;
    UINT32 numSAs;
    IPSEC_SA0 *saList;
    IPSEC_KEYMODULE_STATE0 *keyModuleState;
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 peerV4PrivateAddress;
         /* Empty union arm */ 
        } 	;
    UINT64 mmSaId;
    IPSEC_PFS_GROUP pfsGroup;
    GUID saLookupContext;
    UINT64 qmFilterId;
    } 	IPSEC_SA_BUNDLE1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef /* [v1_enum] */ 
enum IPSEC_TRAFFIC_TYPE_
    {	IPSEC_TRAFFIC_TYPE_TRANSPORT	= 0,
	IPSEC_TRAFFIC_TYPE_TUNNEL	= ( IPSEC_TRAFFIC_TYPE_TRANSPORT + 1 ) ,
	IPSEC_TRAFFIC_TYPE_MAX	= ( IPSEC_TRAFFIC_TYPE_TUNNEL + 1 ) 
    } 	IPSEC_TRAFFIC_TYPE;

typedef struct IPSEC_TRAFFIC0_
    {
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 localV4Address;
        UINT8 localV6Address[ 16 ];
        } 	;
    union 
        {
        UINT32 remoteV4Address;
        UINT8 remoteV6Address[ 16 ];
        } 	;
    IPSEC_TRAFFIC_TYPE trafficType;
    union 
        {
        UINT64 ipsecFilterId;
        UINT64 tunnelPolicyId;
        } 	;
    UINT16 remotePort;
    } 	IPSEC_TRAFFIC0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_TRAFFIC1_
    {
    FWP_IP_VERSION ipVersion;
    union 
        {
        UINT32 localV4Address;
        UINT8 localV6Address[ 16 ];
        } 	;
    union 
        {
        UINT32 remoteV4Address;
        UINT8 remoteV6Address[ 16 ];
        } 	;
    IPSEC_TRAFFIC_TYPE trafficType;
    union 
        {
        UINT64 ipsecFilterId;
        UINT64 tunnelPolicyId;
        } 	;
    UINT16 remotePort;
    UINT16 localPort;
    UINT8 ipProtocol;
    UINT64 localIfLuid;
    UINT32 realIfProfileId;
    } 	IPSEC_TRAFFIC1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_V4_UDP_ENCAPSULATION0_
    {
    UINT16 localUdpEncapPort;
    UINT16 remoteUdpEncapPort;
    } 	IPSEC_V4_UDP_ENCAPSULATION0;

typedef struct IPSEC_GETSPI0_
    {
    IPSEC_TRAFFIC0 inboundIpsecTraffic;
    FWP_IP_VERSION ipVersion;
    union 
        {
        IPSEC_V4_UDP_ENCAPSULATION0 *inboundUdpEncapsulation;
         /* Empty union arm */ 
        } 	;
    IPSEC_CRYPTO_MODULE_ID *rngCryptoModuleID;
    } 	IPSEC_GETSPI0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_GETSPI1_
    {
    IPSEC_TRAFFIC1 inboundIpsecTraffic;
    FWP_IP_VERSION ipVersion;
    union 
        {
        IPSEC_V4_UDP_ENCAPSULATION0 *inboundUdpEncapsulation;
         /* Empty union arm */ 
        } 	;
    IPSEC_CRYPTO_MODULE_ID *rngCryptoModuleID;
    } 	IPSEC_GETSPI1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_VIRTUAL_IF_TUNNEL_INFO0_
    {
    UINT64 virtualIfTunnelId;
    UINT64 trafficSelectorId;
    } 	IPSEC_VIRTUAL_IF_TUNNEL_INFO0;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_DETAILS0_
    {
    FWP_IP_VERSION ipVersion;
    FWP_DIRECTION saDirection;
    IPSEC_TRAFFIC0 traffic;
    IPSEC_SA_BUNDLE0 saBundle;
    union 
        {
        IPSEC_V4_UDP_ENCAPSULATION0 *udpEncapsulation;
         /* Empty union arm */ 
        } 	;
    FWPM_FILTER0 *transportFilter;
    } 	IPSEC_SA_DETAILS0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_DETAILS1_
    {
    FWP_IP_VERSION ipVersion;
    FWP_DIRECTION saDirection;
    IPSEC_TRAFFIC1 traffic;
    IPSEC_SA_BUNDLE1 saBundle;
    union 
        {
        IPSEC_V4_UDP_ENCAPSULATION0 *udpEncapsulation;
         /* Empty union arm */ 
        } 	;
    FWPM_FILTER0 *transportFilter;
    IPSEC_VIRTUAL_IF_TUNNEL_INFO0 virtualIfTunnelInfo;
    } 	IPSEC_SA_DETAILS1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_CONTEXT0_
    {
    UINT64 saContextId;
    IPSEC_SA_DETAILS0 *inboundSa;
    IPSEC_SA_DETAILS0 *outboundSa;
    } 	IPSEC_SA_CONTEXT0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_CONTEXT1_
    {
    UINT64 saContextId;
    IPSEC_SA_DETAILS1 *inboundSa;
    IPSEC_SA_DETAILS1 *outboundSa;
    } 	IPSEC_SA_CONTEXT1;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
typedef struct IPSEC_SA_CONTEXT_ENUM_TEMPLATE0_
    {
    FWP_CONDITION_VALUE0 localSubNet;
    FWP_CONDITION_VALUE0 remoteSubNet;
    } 	IPSEC_SA_CONTEXT_ENUM_TEMPLATE0;

typedef struct IPSEC_SA_ENUM_TEMPLATE0_
    {
    FWP_DIRECTION saDirection;
    } 	IPSEC_SA_ENUM_TEMPLATE0;

typedef /* [v1_enum] */ 
enum IPSEC_FAILURE_POINT_
    {	IPSEC_FAILURE_NONE	= 0,
	IPSEC_FAILURE_ME	= ( IPSEC_FAILURE_NONE + 1 ) ,
	IPSEC_FAILURE_PEER	= ( IPSEC_FAILURE_ME + 1 ) ,
	IPSEC_FAILURE_POINT_MAX	= ( IPSEC_FAILURE_PEER + 1 ) 
    } 	IPSEC_FAILURE_POINT;

typedef struct IPSEC_ADDRESS_INFO0_
    {
    UINT32 numV4Addresses;
    UINT32 *v4Addresses;
    UINT32 numV6Addresses;
    FWP_BYTE_ARRAY16 *v6Addresses;
    } 	IPSEC_ADDRESS_INFO0;

#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_DOSP_FLAG_ENABLE_IKEV1  (0x00000001)
#define IPSEC_DOSP_FLAG_ENABLE_IKEV2  (0x00000002)
#define IPSEC_DOSP_FLAG_DISABLE_AUTHIP  (0x00000004)
#define IPSEC_DOSP_FLAG_DISABLE_DEFAULT_BLOCK  (0x00000008)
#define IPSEC_DOSP_FLAG_FILTER_BLOCK  (0x00000010)
#define IPSEC_DOSP_FLAG_FILTER_EXEMPT  (0x00000020)
#define IPSEC_DOSP_DSCP_DISABLE_VALUE  (0xff)
#define IPSEC_DOSP_RATE_LIMIT_DISABLE_VALUE  (0)
typedef struct IPSEC_DOSP_OPTIONS0_
    {
    UINT32 stateIdleTimeoutSeconds;
    UINT32 perIPRateLimitQueueIdleTimeoutSeconds;
    UINT8 ipV6IPsecUnauthDscp;
    UINT32 ipV6IPsecUnauthRateLimitBytesPerSec;
    UINT32 ipV6IPsecUnauthPerIPRateLimitBytesPerSec;
    UINT8 ipV6IPsecAuthDscp;
    UINT32 ipV6IPsecAuthRateLimitBytesPerSec;
    UINT8 icmpV6Dscp;
    UINT32 icmpV6RateLimitBytesPerSec;
    UINT8 ipV6FilterExemptDscp;
    UINT32 ipV6FilterExemptRateLimitBytesPerSec;
    UINT8 defBlockExemptDscp;
    UINT32 defBlockExemptRateLimitBytesPerSec;
    UINT32 maxStateEntries;
    UINT32 maxPerIPRateLimitQueues;
    UINT32 flags;
    UINT32 numPublicIFLuids;
    UINT64 *publicIFLuids;
    UINT32 numInternalIFLuids;
    UINT64 *internalIFLuids;
    FWP_V6_ADDR_AND_MASK publicV6AddrMask;
    FWP_V6_ADDR_AND_MASK internalV6AddrMask;
    } 	IPSEC_DOSP_OPTIONS0;

typedef struct IPSEC_DOSP_STATISTICS0_
    {
    UINT64 totalStateEntriesCreated;
    UINT64 currentStateEntries;
    UINT64 totalInboundAllowedIPv6IPsecUnauthPkts;
    UINT64 totalInboundRatelimitDiscardedIPv6IPsecUnauthPkts;
    UINT64 totalInboundPerIPRatelimitDiscardedIPv6IPsecUnauthPkts;
    UINT64 totalInboundOtherDiscardedIPv6IPsecUnauthPkts;
    UINT64 totalInboundAllowedIPv6IPsecAuthPkts;
    UINT64 totalInboundRatelimitDiscardedIPv6IPsecAuthPkts;
    UINT64 totalInboundOtherDiscardedIPv6IPsecAuthPkts;
    UINT64 totalInboundAllowedICMPv6Pkts;
    UINT64 totalInboundRatelimitDiscardedICMPv6Pkts;
    UINT64 totalInboundAllowedIPv6FilterExemptPkts;
    UINT64 totalInboundRatelimitDiscardedIPv6FilterExemptPkts;
    UINT64 totalInboundDiscardedIPv6FilterBlockPkts;
    UINT64 totalInboundAllowedDefBlockExemptPkts;
    UINT64 totalInboundRatelimitDiscardedDefBlockExemptPkts;
    UINT64 totalInboundDiscardedDefBlockPkts;
    UINT64 currentInboundIPv6IPsecUnauthPerIPRateLimitQueues;
    } 	IPSEC_DOSP_STATISTICS0;

typedef struct IPSEC_DOSP_STATE0_
    {
    UINT8 publicHostV6Addr[ 16 ];
    UINT8 internalHostV6Addr[ 16 ];
    UINT64 totalInboundIPv6IPsecAuthPackets;
    UINT64 totalOutboundIPv6IPsecAuthPackets;
    UINT32 durationSecs;
    } 	IPSEC_DOSP_STATE0;

typedef struct IPSEC_DOSP_STATE_ENUM_TEMPLATE0_
    {
    FWP_V6_ADDR_AND_MASK publicV6AddrMask;
    FWP_V6_ADDR_AND_MASK internalV6AddrMask;
    } 	IPSEC_DOSP_STATE_ENUM_TEMPLATE0;

#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if _MSC_VER >=  800
#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning(default:4201)
#endif
#endif


extern RPC_IF_HANDLE __MIDL_itf_ipsectypes_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_ipsectypes_0000_0000_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif



