/*
   Copyright (c) Microsoft Corporation

   SYNOPSIS

     Declares version independent definitions for the FWP API.
*/
#include "sdkddkver.h"

#if (NTDDI_VERSION >= NTDDI_WIN6)
#ifndef FWPVI_H
#define FWPVI_H

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Fwpmtypes.
//
///////////////////////////////////////////////////////////////////////////////
#define FWPM_DISPLAY_DATA FWPM_DISPLAY_DATA0
#define FWPM_SESSION FWPM_SESSION0
#define FWPM_SESSION_ENUM_TEMPLATE FWPM_SESSION_ENUM_TEMPLATE0
#define FWPM_PROVIDER FWPM_PROVIDER0
#define FWPM_PROVIDER_ENUM_TEMPLATE FWPM_PROVIDER_ENUM_TEMPLATE0
#define FWPM_PROVIDER_CHANGE FWPM_PROVIDER_CHANGE0
#define FWPM_PROVIDER_SUBSCRIPTION FWPM_PROVIDER_SUBSCRIPTION0
#define FWPM_CLASSIFY_OPTION FWPM_CLASSIFY_OPTION0
#define FWPM_CLASSIFY_OPTIONS FWPM_CLASSIFY_OPTIONS0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_PROVIDER_CONTEXT FWPM_PROVIDER_CONTEXT1
#else
#define FWPM_PROVIDER_CONTEXT FWPM_PROVIDER_CONTEXT0
#endif
#define FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0
#define FWPM_PROVIDER_CONTEXT_CHANGE FWPM_PROVIDER_CONTEXT_CHANGE0
#define FWPM_PROVIDER_CONTEXT_SUBSCRIPTION FWPM_PROVIDER_CONTEXT_SUBSCRIPTION0
#define FWPM_SUBLAYER FWPM_SUBLAYER0
#define FWPM_SUBLAYER_ENUM_TEMPLATE FWPM_SUBLAYER_ENUM_TEMPLATE0
#define FWPM_SUBLAYER_CHANGE FWPM_SUBLAYER_CHANGE0
#define FWPM_SUBLAYER_SUBSCRIPTION FWPM_SUBLAYER_SUBSCRIPTION0
#define FWPM_FIELD FWPM_FIELD0
#define FWPM_LAYER FWPM_LAYER0
#define FWPM_LAYER_ENUM_TEMPLATE FWPM_LAYER_ENUM_TEMPLATE0
#define FWPM_CALLOUT FWPM_CALLOUT0
#define FWPM_CALLOUT_ENUM_TEMPLATE FWPM_CALLOUT_ENUM_TEMPLATE0
#define FWPM_CALLOUT_CHANGE FWPM_CALLOUT_CHANGE0
#define FWPM_CALLOUT_SUBSCRIPTION FWPM_CALLOUT_SUBSCRIPTION0
#define FWPM_ACTION FWPM_ACTION0
#define FWPM_FILTER_CONDITION FWPM_FILTER_CONDITION0
#define FWPM_FILTER FWPM_FILTER0
#define FWPM_FILTER_ENUM_TEMPLATE FWPM_FILTER_ENUM_TEMPLATE0
#define FWPM_FILTER_CHANGE FWPM_FILTER_CHANGE0
#define FWPM_FILTER_SUBSCRIPTION FWPM_FILTER_SUBSCRIPTION0
#define FWPM_LAYER_STATISTICS FWPM_LAYER_STATISTICS0
#define FWPM_STATISTICS FWPM_STATISTICS0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_NET_EVENT_HEADER FWPM_NET_EVENT_HEADER1
#define FWPM_NET_EVENT_IKEEXT_MM_FAILURE FWPM_NET_EVENT_IKEEXT_MM_FAILURE1
#define FWPM_NET_EVENT_IKEEXT_EM_FAILURE FWPM_NET_EVENT_IKEEXT_EM_FAILURE1
#else
#define FWPM_NET_EVENT_HEADER FWPM_NET_EVENT_HEADER0
#define FWPM_NET_EVENT_IKEEXT_MM_FAILURE FWPM_NET_EVENT_IKEEXT_MM_FAILURE0
#define FWPM_NET_EVENT_IKEEXT_EM_FAILURE FWPM_NET_EVENT_IKEEXT_EM_FAILURE0
#endif
#define FWPM_NET_EVENT_IKEEXT_QM_FAILURE FWPM_NET_EVENT_IKEEXT_QM_FAILURE0
#define FWPM_NET_EVENT_IPSEC_KERNEL_DROP FWPM_NET_EVENT_IPSEC_KERNEL_DROP0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_NET_EVENT_CLASSIFY_DROP FWPM_NET_EVENT_CLASSIFY_DROP1
#define FWPM_NET_EVENT_IPSEC_DOSP_DROP FWPM_NET_EVENT_IPSEC_DOSP_DROP0
#define FWPM_NET_EVENT FWPM_NET_EVENT1
#else
#define FWPM_NET_EVENT_CLASSIFY_DROP FWPM_NET_EVENT_CLASSIFY_DROP0
#define FWPM_NET_EVENT FWPM_NET_EVENT0
#endif
#define FWPM_NET_EVENT_ENUM_TEMPLATE FWPM_NET_EVENT_ENUM_TEMPLATE0
#define FWPM_NET_EVENT_SUBSCRIPTION FWPM_NET_EVENT_SUBSCRIPTION0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_SYSTEM_PORTS_BY_TYPE FWPM_SYSTEM_PORTS_BY_TYPE0
#define FWPM_SYSTEM_PORTS FWPM_SYSTEM_PORTS0
#endif

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Fwpstypes.
//
///////////////////////////////////////////////////////////////////////////////
#define FWPS_FILTER_CONDITION FWPS_FILTER_CONDITION0
#define FWPS_ACTION FWPS_ACTION0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_FILTER FWPS_FILTER1
#else
#define FWPS_FILTER FWPS_FILTER0
#endif
#define FWPS_INCOMING_VALUE FWPS_INCOMING_VALUE0
#define FWPS_INCOMING_VALUES FWPS_INCOMING_VALUES0
#define FWPS_DISCARD_METADATA FWPS_DISCARD_METADATA0
#define FWPS_INBOUND_FRAGMENT_METADATA FWPS_INBOUND_FRAGMENT_METADATA0
#define FWPS_CLASSIFY_OUT FWPS_CLASSIFY_OUT0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_ALE_ENDPOINT_PROPERTIES FWPS_ALE_ENDPOINT_PROPERTIES0
#define FWPS_ALE_ENDPOINT_ENUM_TEMPLATE FWPS_ALE_ENDPOINT_ENUM_TEMPLATE0
#endif

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Fwptypes.
//
///////////////////////////////////////////////////////////////////////////////
#define FWP_VALUE  FWP_VALUE0
#define FWP_RANGE  FWP_RANGE0
#define FWP_CONDITION_VALUE  FWP_CONDITION_VALUE0

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Iketypes.
//
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_PRESHARED_KEY_AUTHENTICATION IKEEXT_PRESHARED_KEY_AUTHENTICATION1
#else
#define IKEEXT_PRESHARED_KEY_AUTHENTICATION IKEEXT_PRESHARED_KEY_AUTHENTICATION0
#endif
#define IKEEXT_CERT_ROOT_CONFIG IKEEXT_CERT_ROOT_CONFIG0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_CERTIFICATE_AUTHENTICATION IKEEXT_CERTIFICATE_AUTHENTICATION1
#else
#define IKEEXT_CERTIFICATE_AUTHENTICATION IKEEXT_CERTIFICATE_AUTHENTICATION0
#endif
#define IKEEXT_IPV6_CGA_AUTHENTICATION IKEEXT_IPV6_CGA_AUTHENTICATION0
#define IKEEXT_KERBEROS_AUTHENTICATION IKEEXT_KERBEROS_AUTHENTICATION0
#define IKEEXT_NTLM_V2_AUTHENTICATION IKEEXT_NTLM_V2_AUTHENTICATION0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_EAP_AUTHENTICATION IKEEXT_EAP_AUTHENTICATION0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_AUTHENTICATION_METHOD IKEEXT_AUTHENTICATION_METHOD1
#else
#define IKEEXT_AUTHENTICATION_METHOD IKEEXT_AUTHENTICATION_METHOD0
#endif
#define IKEEXT_CIPHER_ALGORITHM IKEEXT_CIPHER_ALGORITHM0
#define IKEEXT_INTEGRITY_ALGORITHM IKEEXT_INTEGRITY_ALGORITHM0
#define IKEEXT_PROPOSAL IKEEXT_PROPOSAL0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_POLICY IKEEXT_POLICY1
#else
#define IKEEXT_POLICY IKEEXT_POLICY0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_EM_POLICY IKEEXT_EM_POLICY1
#else
#define IKEEXT_EM_POLICY IKEEXT_EM_POLICY0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_IP_VERSION_SPECIFIC_KEYMODULE_STATISTICS IKEEXT_IP_VERSION_SPECIFIC_KEYMODULE_STATISTICS1
#else
#define IKEEXT_IP_VERSION_SPECIFIC_KEYMODULE_STATISTICS IKEEXT_IP_VERSION_SPECIFIC_KEYMODULE_STATISTICS0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_KEYMODULE_STATISTICS IKEEXT_KEYMODULE_STATISTICS1
#else
#define IKEEXT_KEYMODULE_STATISTICS IKEEXT_KEYMODULE_STATISTICS0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_IP_VERSION_SPECIFIC_COMMON_STATISTICS IKEEXT_IP_VERSION_SPECIFIC_COMMON_STATISTICS1
#else
#define IKEEXT_IP_VERSION_SPECIFIC_COMMON_STATISTICS IKEEXT_IP_VERSION_SPECIFIC_COMMON_STATISTICS0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_COMMON_STATISTICS IKEEXT_COMMON_STATISTICS1
#else
#define IKEEXT_COMMON_STATISTICS IKEEXT_COMMON_STATISTICS0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_STATISTICS IKEEXT_STATISTICS1
#else
#define IKEEXT_STATISTICS IKEEXT_STATISTICS0
#endif
#define IKEEXT_TRAFFIC IKEEXT_TRAFFIC0
#define IKEEXT_COOKIE_PAIR IKEEXT_COOKIE_PAIR0
#define IKEEXT_NAME_CREDENTIAL IKEEXT_NAME_CREDENTIAL0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_CERTIFICATE_CREDENTIAL IKEEXT_CERTIFICATE_CREDENTIAL1
#define IKEEXT_CREDENTIAL IKEEXT_CREDENTIAL1
#define IKEEXT_CREDENTIAL_PAIR IKEEXT_CREDENTIAL_PAIR1
#define IKEEXT_CREDENTIALS IKEEXT_CREDENTIALS1
#else
#define IKEEXT_CERTIFICATE_CREDENTIAL IKEEXT_CERTIFICATE_CREDENTIAL0
#define IKEEXT_CREDENTIAL IKEEXT_CREDENTIAL0
#define IKEEXT_CREDENTIAL_PAIR IKEEXT_CREDENTIAL_PAIR0
#define IKEEXT_CREDENTIALS IKEEXT_CREDENTIALS0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IKEEXT_SA_DETAILS IKEEXT_SA_DETAILS1
#else
#define IKEEXT_SA_DETAILS IKEEXT_SA_DETAILS0
#endif
#define IKEEXT_SA_ENUM_TEMPLATE IKEEXT_SA_ENUM_TEMPLATE0

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Ipsectypes.
//
///////////////////////////////////////////////////////////////////////////////
#define IPSEC_SA_LIFETIME IPSEC_SA_LIFETIME0
#define IPSEC_AUTH_TRANSFORM_ID IPSEC_AUTH_TRANSFORM_ID0
#define IPSEC_AUTH_TRANSFORM IPSEC_AUTH_TRANSFORM0
#define IPSEC_CIPHER_TRANSFORM_ID IPSEC_CIPHER_TRANSFORM_ID0
#define IPSEC_CIPHER_TRANSFORM IPSEC_CIPHER_TRANSFORM0
#define IPSEC_AUTH_AND_CIPHER_TRANSFORM IPSEC_AUTH_AND_CIPHER_TRANSFORM0
#define IPSEC_SA_TRANSFORM IPSEC_SA_TRANSFORM0
#define IPSEC_PROPOSAL IPSEC_PROPOSAL0
#define IPSEC_SA_IDLE_TIMEOUT IPSEC_SA_IDLE_TIMEOUT0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_TRANSPORT_POLICY IPSEC_TRANSPORT_POLICY1
#define IPSEC_TUNNEL_ENDPOINTS IPSEC_TUNNEL_ENDPOINTS1
#define IPSEC_TUNNEL_POLICY IPSEC_TUNNEL_POLICY1
#else
#define IPSEC_TRANSPORT_POLICY IPSEC_TRANSPORT_POLICY0
#define IPSEC_TUNNEL_ENDPOINTS IPSEC_TUNNEL_ENDPOINTS0
#define IPSEC_TUNNEL_POLICY IPSEC_TUNNEL_POLICY0
#endif
#define IPSEC_KEYING_POLICY IPSEC_KEYING_POLICY0
#define IPSEC_AGGREGATE_SA_STATISTICS IPSEC_AGGREGATE_SA_STATISTICS0
#define IPSEC_ESP_DROP_PACKET_STATISTICS IPSEC_ESP_DROP_PACKET_STATISTICS0
#define IPSEC_AH_DROP_PACKET_STATISTICS IPSEC_AH_DROP_PACKET_STATISTICS0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_AGGREGATE_DROP_PACKET_STATISTICS IPSEC_AGGREGATE_DROP_PACKET_STATISTICS1
#define IPSEC_TRAFFIC_STATISTICS IPSEC_TRAFFIC_STATISTICS1
#define IPSEC_STATISTICS IPSEC_STATISTICS1
#else
#define IPSEC_AGGREGATE_DROP_PACKET_STATISTICS IPSEC_AGGREGATE_DROP_PACKET_STATISTICS0
#define IPSEC_TRAFFIC_STATISTICS IPSEC_TRAFFIC_STATISTICS0
#define IPSEC_STATISTICS IPSEC_STATISTICS0
#endif
#define IPSEC_SA_AUTH_INFORMATION IPSEC_SA_AUTH_INFORMATION0
#define IPSEC_SA_CIPHER_INFORMATION IPSEC_SA_CIPHER_INFORMATION0
#define IPSEC_SA_AUTH_AND_CIPHER_INFORMATION IPSEC_SA_AUTH_AND_CIPHER_INFORMATION0
#define IPSEC_SA IPSEC_SA0
#define IPSEC_KEYMODULE_STATE IPSEC_KEYMODULE_STATE0
#define IPSEC_TOKEN IPSEC_TOKEN0
#define IPSEC_ID IPSEC_ID0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_TRAFFIC IPSEC_TRAFFIC1
#define IPSEC_SA_BUNDLE IPSEC_SA_BUNDLE1
#else
#define IPSEC_TRAFFIC IPSEC_TRAFFIC0
#define IPSEC_SA_BUNDLE IPSEC_SA_BUNDLE0
#endif
#define IPSEC_V4_UDP_ENCAPSULATION IPSEC_V4_UDP_ENCAPSULATION0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_GETSPI IPSEC_GETSPI1
#define IPSEC_SA_DETAILS IPSEC_SA_DETAILS1
#define IPSEC_SA_CONTEXT IPSEC_SA_CONTEXT1
#else
#define IPSEC_GETSPI IPSEC_GETSPI0
#define IPSEC_SA_DETAILS IPSEC_SA_DETAILS0
#define IPSEC_SA_CONTEXT IPSEC_SA_CONTEXT0
#endif
#define IPSEC_SA_CONTEXT_ENUM_TEMPLATE IPSEC_SA_CONTEXT_ENUM_TEMPLATE0
#define IPSEC_SA_ENUM_TEMPLATE IPSEC_SA_ENUM_TEMPLATE0
#define IPSEC_ADDRESS_INFO IPSEC_ADDRESS_INFO0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPSEC_VIRTUAL_IF_TUNNEL_INFO IPSEC_VIRTUAL_IF_TUNNEL_INFO0
#define IPSEC_DOSP_OPTIONS IPSEC_DOSP_OPTIONS0
#define IPSEC_DOSP_STATISTICS IPSEC_DOSP_STATISTICS0
#define IPSEC_DOSP_STATE IPSEC_DOSP_STATE0
#define IPSEC_DOSP_STATE_ENUM_TEMPLATE IPSEC_DOSP_STATE_ENUM_TEMPLATE0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Fwpmu / Fwpmk
//
///////////////////////////////////////////////////////////////////////////////
#define FWPM_SERVICE_STATE_CHANGE_CALLBACK FWPM_SERVICE_STATE_CHANGE_CALLBACK0
#define FwpmFreeMemory FwpmFreeMemory0
#define FwpmBfeStateGet FwpmBfeStateGet0
#define FwpmBfeStateSubscribeChanges FwpmBfeStateSubscribeChanges0
#define FwpmBfeStateUnsubscribeChanges FwpmBfeStateUnsubscribeChanges0
#define FwpmEngineOpen FwpmEngineOpen0
#define FwpmEngineClose FwpmEngineClose0
#define FwpmEngineGetOption FwpmEngineGetOption0
#define FwpmEngineSetOption FwpmEngineSetOption0
#define FwpmEngineGetSecurityInfo FwpmEngineGetSecurityInfo0
#define FwpmEngineSetSecurityInfo FwpmEngineSetSecurityInfo0
#define FwpmSessionCreateEnumHandle FwpmSessionCreateEnumHandle0
#define FwpmSessionEnum FwpmSessionEnum0
#define FwpmSessionDestroyEnumHandle FwpmSessionDestroyEnumHandle0
#define FwpmTransactionBegin FwpmTransactionBegin0
#define FwpmTransactionCommit FwpmTransactionCommit0
#define FwpmTransactionAbort FwpmTransactionAbort0
#define FwpmProviderAdd FwpmProviderAdd0
#define FwpmProviderDeleteByKey FwpmProviderDeleteByKey0
#define FwpmProviderGetByKey FwpmProviderGetByKey0
#define FwpmProviderCreateEnumHandle FwpmProviderCreateEnumHandle0
#define FwpmProviderEnum FwpmProviderEnum0
#define FwpmProviderDestroyEnumHandle FwpmProviderDestroyEnumHandle0
#define FwpmProviderGetSecurityInfoByKey FwpmProviderGetSecurityInfoByKey0
#define FwpmProviderSetSecurityInfoByKey FwpmProviderSetSecurityInfoByKey0
#define FWPM_PROVIDER_CHANGE_CALLBACK FWPM_PROVIDER_CHANGE_CALLBACK0
#define FwpmProviderSubscribeChanges FwpmProviderSubscribeChanges0
#define FwpmProviderUnsubscribeChanges FwpmProviderUnsubscribeChanges0
#define FwpmProviderSubscriptionsGet FwpmProviderSubscriptionsGet0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpmProviderContextAdd FwpmProviderContextAdd1
#define FwpmProviderContextGetById FwpmProviderContextGetById1
#define FwpmProviderContextGetByKey FwpmProviderContextGetByKey1
#define FwpmProviderContextEnum FwpmProviderContextEnum1
#else
#define FwpmProviderContextAdd FwpmProviderContextAdd0
#define FwpmProviderContextGetById FwpmProviderContextGetById0
#define FwpmProviderContextGetByKey FwpmProviderContextGetByKey0
#define FwpmProviderContextEnum FwpmProviderContextEnum0
#endif
#define FwpmProviderContextDeleteById FwpmProviderContextDeleteById0
#define FwpmProviderContextDeleteByKey FwpmProviderContextDeleteByKey0
#define FwpmProviderContextCreateEnumHandle FwpmProviderContextCreateEnumHandle0
#define FwpmProviderContextDestroyEnumHandle FwpmProviderContextDestroyEnumHandle0
#define FwpmProviderContextGetSecurityInfoByKey FwpmProviderContextGetSecurityInfoByKey0
#define FwpmProviderContextSetSecurityInfoByKey FwpmProviderContextSetSecurityInfoByKey0
#define FWPM_PROVIDER_CONTEXT_CHANGE_CALLBACK FWPM_PROVIDER_CONTEXT_CHANGE_CALLBACK0
#define FwpmProviderContextSubscribeChanges FwpmProviderContextSubscribeChanges0
#define FwpmProviderContextUnsubscribeChanges FwpmProviderContextUnsubscribeChanges0
#define FwpmProviderContextSubscriptionsGet FwpmProviderContextSubscriptionsGet0
#define FwpmSubLayerAdd FwpmSubLayerAdd0
#define FwpmSubLayerDeleteByKey FwpmSubLayerDeleteByKey0
#define FwpmSubLayerGetByKey FwpmSubLayerGetByKey0
#define FwpmSubLayerCreateEnumHandle FwpmSubLayerCreateEnumHandle0
#define FwpmSubLayerEnum FwpmSubLayerEnum0
#define FwpmSubLayerDestroyEnumHandle FwpmSubLayerDestroyEnumHandle0
#define FwpmSubLayerGetSecurityInfoByKey FwpmSubLayerGetSecurityInfoByKey0
#define FwpmSubLayerSetSecurityInfoByKey FwpmSubLayerSetSecurityInfoByKey0
#define FWPM_SUBLAYER_CHANGE_CALLBACK FWPM_SUBLAYER_CHANGE_CALLBACK0
#define FwpmSubLayerSubscribeChanges FwpmSubLayerSubscribeChanges0
#define FwpmSubLayerUnsubscribeChanges FwpmSubLayerUnsubscribeChanges0
#define FwpmSubLayerSubscriptionsGet FwpmSubLayerSubscriptionsGet0
#define FwpmLayerGetById FwpmLayerGetById0
#define FwpmLayerGetByKey FwpmLayerGetByKey0
#define FwpmLayerCreateEnumHandle FwpmLayerCreateEnumHandle0
#define FwpmLayerEnum FwpmLayerEnum0
#define FwpmLayerDestroyEnumHandle FwpmLayerDestroyEnumHandle0
#define FwpmLayerGetSecurityInfoByKey FwpmLayerGetSecurityInfoByKey0
#define FwpmLayerSetSecurityInfoByKey FwpmLayerSetSecurityInfoByKey0
#define FwpmCalloutAdd FwpmCalloutAdd0
#define FwpmCalloutDeleteById FwpmCalloutDeleteById0
#define FwpmCalloutDeleteByKey FwpmCalloutDeleteByKey0
#define FwpmCalloutGetById FwpmCalloutGetById0
#define FwpmCalloutGetByKey FwpmCalloutGetByKey0
#define FwpmCalloutCreateEnumHandle FwpmCalloutCreateEnumHandle0
#define FwpmCalloutEnum FwpmCalloutEnum0
#define FwpmCalloutDestroyEnumHandle FwpmCalloutDestroyEnumHandle0
#define FwpmCalloutGetSecurityInfoByKey FwpmCalloutGetSecurityInfoByKey0
#define FwpmCalloutSetSecurityInfoByKey FwpmCalloutSetSecurityInfoByKey0
#define FWPM_CALLOUT_CHANGE_CALLBACK FWPM_CALLOUT_CHANGE_CALLBACK0
#define FwpmCalloutSubscribeChanges FwpmCalloutSubscribeChanges0
#define FwpmCalloutUnsubscribeChanges FwpmCalloutUnsubscribeChanges0
#define FwpmCalloutSubscriptionsGet FwpmCalloutSubscriptionsGet0
#define FwpmFilterAdd FwpmFilterAdd0
#define FwpmFilterDeleteById FwpmFilterDeleteById0
#define FwpmFilterDeleteByKey FwpmFilterDeleteByKey0
#define FwpmFilterGetById FwpmFilterGetById0
#define FwpmFilterGetByKey FwpmFilterGetByKey0
#define FwpmFilterCreateEnumHandle FwpmFilterCreateEnumHandle0
#define FwpmFilterEnum FwpmFilterEnum0
#define FwpmFilterDestroyEnumHandle FwpmFilterDestroyEnumHandle0
#define FwpmFilterGetSecurityInfoByKey FwpmFilterGetSecurityInfoByKey0
#define FwpmFilterSetSecurityInfoByKey FwpmFilterSetSecurityInfoByKey0
#define FWPM_FILTER_CHANGE_CALLBACK FWPM_FILTER_CHANGE_CALLBACK0
#define FwpmFilterSubscribeChanges FwpmFilterSubscribeChanges0
#define FwpmFilterUnsubscribeChanges FwpmFilterUnsubscribeChanges0
#define FwpmFilterSubscriptionsGet FwpmFilterSubscriptionsGet0
#define FwpmGetAppIdFromFileName FwpmGetAppIdFromFileName0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpmIPsecTunnelAdd FwpmIPsecTunnelAdd1
#else
#define FwpmIPsecTunnelAdd FwpmIPsecTunnelAdd0
#endif
#define FwpmIPsecTunnelDeleteByKey FwpmIPsecTunnelDeleteByKey0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecGetStatistics IPsecGetStatistics1
#define IPsecSaContextCreate IPsecSaContextCreate1
#else
#define IPsecGetStatistics IPsecGetStatistics0
#define IPsecSaContextCreate IPsecSaContextCreate0
#endif
#define IPsecSaContextDeleteById IPsecSaContextDeleteById0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecSaContextGetById IPsecSaContextGetById1
#define IPsecSaContextGetSpi IPsecSaContextGetSpi1
#define IPsecSaContextSetSpi IPsecSaContextSetSpi0
#define IPsecSaContextAddInbound IPsecSaContextAddInbound1
#define IPsecSaContextAddOutbound IPsecSaContextAddOutbound1
#else
#define IPsecSaContextGetById IPsecSaContextGetById0
#define IPsecSaContextGetSpi IPsecSaContextGetSpi0
#define IPsecSaContextAddInbound IPsecSaContextAddInbound0
#define IPsecSaContextAddOutbound IPsecSaContextAddOutbound0
#endif
#define IPsecSaContextExpire IPsecSaContextExpire0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecSaContextUpdate IPsecSaContextUpdate0
#endif
#define IPsecSaContextCreateEnumHandle IPsecSaContextCreateEnumHandle0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecSaContextEnum IPsecSaContextEnum1
#else
#define IPsecSaContextEnum IPsecSaContextEnum0
#endif
#define IPsecSaContextDestroyEnumHandle IPsecSaContextDestroyEnumHandle0
#define IPsecSaCreateEnumHandle IPsecSaCreateEnumHandle0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecSaEnum IPsecSaEnum1
#else
#define IPsecSaEnum IPsecSaEnum0
#endif
#define IPsecSaDestroyEnumHandle IPsecSaDestroyEnumHandle0
#define IPsecSaDbGetSecurityInfo IPsecSaDbGetSecurityInfo0
#define IPsecSaDbSetSecurityInfo IPsecSaDbSetSecurityInfo0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IPsecDospGetStatistics IPsecDospGetStatistics0
#define IPsecDospStateCreateEnumHandle IPsecDospStateCreateEnumHandle0
#define IPsecDospStateEnum IPsecDospStateEnum0
#define IPsecDospStateDestroyEnumHandle IPsecDospStateDestroyEnumHandle0
#define IPsecDospGetSecurityInfo IPsecDospGetSecurityInfo0
#define IPsecDospSetSecurityInfo IPsecDospSetSecurityInfo0
#endif
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IkeextGetStatistics IkeextGetStatistics1
#else
#define IkeextGetStatistics IkeextGetStatistics0
#endif
#define IkeextSaDeleteById IkeextSaDeleteById0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IkeextSaGetById IkeextSaGetById1
#else
#define IkeextSaGetById IkeextSaGetById0
#endif
#define IkeextSaCreateEnumHandle IkeextSaCreateEnumHandle0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define IkeextSaEnum IkeextSaEnum1
#else
#define IkeextSaEnum IkeextSaEnum0
#endif
#define IkeextSaDestroyEnumHandle IkeextSaDestroyEnumHandle0
#define IkeextSaDbGetSecurityInfo IkeextSaDbGetSecurityInfo0
#define IkeextSaDbSetSecurityInfo IkeextSaDbSetSecurityInfo0
#define FwpmNetEventCreateEnumHandle FwpmNetEventCreateEnumHandle0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpmNetEventEnum FwpmNetEventEnum1
#else
#define FwpmNetEventEnum FwpmNetEventEnum0
#endif
#define FwpmNetEventDestroyEnumHandle FwpmNetEventDestroyEnumHandle0
#define FwpmNetEventsGetSecurityInfo FwpmNetEventsGetSecurityInfo0
#define FwpmNetEventsSetSecurityInfo FwpmNetEventsSetSecurityInfo0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPM_NET_EVENT_CALLBACK FWPM_NET_EVENT_CALLBACK0
#define FwpmNetEventSubscribe FwpmNetEventSubscribe0
#define FwpmNetEventUnsubscribe FwpmNetEventUnsubscribe0
#define FwpmNetEventSubscriptionsGet FwpmNetEventSubscriptionsGet0
#define FwpmSystemPortsGet FwpmSystemPortsGet0
#define FWPM_SYSTEM_PORTS_CALLBACK FWPM_SYSTEM_PORTS_CALLBACK0
#define FwpmSystemPortsSubscribe FwpmSystemPortsSubscribe0
#define FwpmSystemPortsUnsubscribe FwpmSystemPortsUnsubscribe0
#endif

///////////////////////////////////////////////////////////////////////////////
//
// Version independent definitions for Fwpsu / Fwpsk
//
///////////////////////////////////////////////////////////////////////////////
#define FWPS_INCOMING_METADATA_VALUES FWPS_INCOMING_METADATA_VALUES0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_CALLOUT_CLASSIFY_FN FWPS_CALLOUT_CLASSIFY_FN1
#else
#define FWPS_CALLOUT_CLASSIFY_FN FWPS_CALLOUT_CLASSIFY_FN0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_CALLOUT_NOTIFY_FN FWPS_CALLOUT_NOTIFY_FN1
#else
#define FWPS_CALLOUT_NOTIFY_FN FWPS_CALLOUT_NOTIFY_FN0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0
#define FWPS_CALLOUT_BOOTTIME_CALLOUT_DELETE_NOTIFY_FN FWPS_CALLOUT_BOOTTIME_CALLOUT_DELETE_NOTIFY_FN0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_CALLOUT FWPS_CALLOUT1
#else
#define FWPS_CALLOUT FWPS_CALLOUT0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpsCalloutRegister FwpsCalloutRegister1
#else
#define FwpsCalloutRegister FwpsCalloutRegister0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpsCalloutUnregisterById FwpsCalloutUnregisterById0
#define FwpsCalloutUnregisterByKey FwpsCalloutUnregisterByKey0
#define FwpsFlowAssociateContext FwpsFlowAssociateContext0
#define FwpsFlowRemoveContext FwpsFlowRemoveContext0
#define FWPS_PACKET_LIST_INBOUND_IPSEC_INFORMATION FWPS_PACKET_LIST_INBOUND_IPSEC_INFORMATION0
#define FWPS_PACKET_LIST_OUTBOUND_IPSEC_INFORMATION FWPS_PACKET_LIST_OUTBOUND_IPSEC_INFORMATION0
#define FWPS_PACKET_LIST_IPSEC_INFORMATION FWPS_PACKET_LIST_IPSEC_INFORMATION0
#define FWPS_PACKET_LIST_FWP_INFORMATION FWPS_PACKET_LIST_FWP_INFORMATION0
#define FWPS_PACKET_LIST_INFORMATION FWPS_PACKET_LIST_INFORMATION0
#define FwpsGetPacketListSecurityInformation FwpsGetPacketListSecurityInformation0
#define FwpsPendOperation FwpsPendOperation0
#define FwpsCompleteOperation FwpsCompleteOperation0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpsAcquireClassifyHandle FwpsAcquireClassifyHandle0
#define FwpsReleaseClassifyHandle FwpsReleaseClassifyHandle0
#define FwpsPendClassify FwpsPendClassify0
#define FwpsCompleteClassify FwpsCompleteClassify0
#define FwpsAcquireWritableLayerDataPointer FwpsAcquireWritableLayerDataPointer0
#define FwpsApplyModifiedLayerData FwpsApplyModifiedLayerData0
#define FWPS_CONNECT_REQUEST FWPS_CONNECT_REQUEST0
#define FWPS_BIND_REQUEST FWPS_BIND_REQUEST0
#define FWPS_NET_BUFFER_LIST_EVENT_TYPE FWPS_NET_BUFFER_LIST_EVENT_TYPE0
#define FWPS_NET_BUFFER_LIST_NOTIFY_FN FWPS_NET_BUFFER_LIST_NOTIFY_FN0
#define FwpsNetBufferListGetTagForContext FwpsNetBufferListGetTagForContext0
#define FwpsNetBufferListAssociateContext FwpsNetBufferListAssociateContext0
#define FwpsNetBufferListRetrieveContext FwpsNetBufferListRetrieveContext0
#define FwpsNetBufferListRemoveContext FwpsNetBufferListRemoveContext0
#define FwpsOpenToken FwpsOpenToken0
#define FwpsAleEndpointGetById FwpsAleEndpointGetById0
#define FwpsAleEndpointCreateEnumHandle FwpsAleEndpointCreateEnumHandle0
#define FwpsAleEndpointEnum FwpsAleEndpointEnum0
#define FwpsAleEndpointDestroyEnumHandle FwpsAleEndpointDestroyEnumHandle0
#define FwpsAleEndpointGetSecurityInfo FwpsAleEndpointGetSecurityInfo0
#define FwpsAleEndpointSetSecurityInfo FwpsAleEndpointSetSecurityInfo0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpsClassifyOptionSet FwpsClassifyOptionSet0
#define FwpsInjectionHandleCreate FwpsInjectionHandleCreate0
#define FwpsInjectionHandleDestroy FwpsInjectionHandleDestroy0
#define FWPS_INJECT_COMPLETE FWPS_INJECT_COMPLETE0
#define FwpsAllocateNetBufferAndNetBufferList FwpsAllocateNetBufferAndNetBufferList0
#define FwpsFreeNetBufferList FwpsFreeNetBufferList0
#define FwpsAllocateCloneNetBufferList FwpsAllocateCloneNetBufferList0
#define FwpsFreeCloneNetBufferList FwpsFreeCloneNetBufferList0
#define FwpsReassembleForwardFragmentGroup FwpsReassembleForwardFragmentGroup0
#define FwpsInjectNetworkSendAsync FwpsInjectNetworkSendAsync0
#define FwpsInjectForwardAsync FwpsInjectForwardAsync0
#define FwpsConstructIpHeaderForTransportPacket FwpsConstructIpHeaderForTransportPacket0
#if (NTDDI_VERSION >= NTDDI_WIN7)
#define FWPS_TRANSPORT_SEND_PARAMS FWPS_TRANSPORT_SEND_PARAMS1
#define FwpsInjectTransportSendAsync FwpsInjectTransportSendAsync1
#else
#define FWPS_TRANSPORT_SEND_PARAMS FWPS_TRANSPORT_SEND_PARAMS0
#define FwpsInjectTransportSendAsync FwpsInjectTransportSendAsync0
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
#define FwpsInjectTransportReceiveAsync FwpsInjectTransportReceiveAsync0
#define FwpsInjectNetworkReceiveAsync FwpsInjectNetworkReceiveAsync0
#define FwpsReferenceNetBufferList FwpsReferenceNetBufferList0
#define FwpsDereferenceNetBufferList FwpsDereferenceNetBufferList0
#define FwpsQueryPacketInjectionState FwpsQueryPacketInjectionState0
#define FWPS_STREAM_DATA_OFFSET FWPS_STREAM_DATA_OFFSET0
#define FWPS_STREAM_DATA FWPS_STREAM_DATA0
#define FWPS_STREAM_CALLOUT_IO_PACKET FWPS_STREAM_CALLOUT_IO_PACKET0
#define FwpsStreamInjectAsync FwpsStreamInjectAsync0
#define FwpsStreamContinue FwpsStreamContinue0
#define FwpsCopyStreamDataToBuffer FwpsCopyStreamDataToBuffer0
#define FwpsCloneStreamData FwpsCloneStreamData0
#define FwpsDiscardClonedStreamData FwpsDiscardClonedStreamData0

#endif // FWPVI_H
#endif // (NTDDI_VERSION >= NTDDI_WIN6)


