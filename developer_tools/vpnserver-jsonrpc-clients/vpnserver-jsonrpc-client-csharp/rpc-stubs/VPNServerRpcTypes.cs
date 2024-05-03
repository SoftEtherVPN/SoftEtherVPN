// SoftEther VPN Server JSON-RPC Stub code for C#
// 
// VPNServerRpcTypes.cs - Data Type Definition for SoftEther VPN Server JSON-RPC Stubs
//
// Automatically generated at 2023-05-10 14:43:37 by vpnserver-jsonrpc-codegen
//
// Licensed under the Apache License 2.0
// Copyright (c) 2014-2023 SoftEther VPN Project

using System;
using Newtonsoft.Json;

namespace SoftEther.VPNServerRpc
{
    /// <summary>
    /// IP Protocol Numbers
    /// </summary>
    public enum VpnIpProtocolNumber
    {
        /// <summary>
        /// ICMP for IPv4
        /// </summary>
        ICMPv4 = 1,

        /// <summary>
        ///  TCP
        /// </summary>
        TCP = 6,

        /// <summary>
        ///  UDP
        /// </summary>
        UDP = 17,

        /// <summary>
        /// ICMP for IPv6
        /// </summary>
        ICMPv6 = 58,
    }

    /// <summary>
    /// The body of the Access list
    /// </summary>
    public class VpnAccess
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// Specify a description (note) for this rule
        /// </summary>
        public string Note_utf;

        /// <summary>
        /// Enabled flag (true: enabled, false: disabled)
        /// </summary>
        public bool Active_bool;

        /// <summary>
        /// Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values.
        /// </summary>
        public uint Priority_u32;

        /// <summary>
        /// The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded.
        /// </summary>
        public bool Discard_bool;

        /// <summary>
        /// The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6.
        /// </summary>
        public bool IsIPv6_bool;

        /// <summary>
        /// Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field.
        /// </summary>
        public string SrcIpAddress_ip;

        /// <summary>
        /// Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
        /// </summary>
        public string SrcSubnetMask_ip;

        /// <summary>
        /// Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field.
        /// </summary>
        public string DestIpAddress_ip;

        /// <summary>
        /// Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
        /// </summary>
        public string DestSubnetMask_ip;

        /// <summary>
        /// Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field.
        /// </summary>
        public byte[] SrcIpAddress6_bin;

        /// <summary>
        /// Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
        /// </summary>
        public byte[] SrcSubnetMask6_bin;

        /// <summary>
        /// Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field.
        /// </summary>
        public byte[] DestIpAddress6_bin;

        /// <summary>
        /// Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
        /// </summary>
        public byte[] DestSubnetMask6_bin;

        /// <summary>
        /// The IP protocol number
        /// </summary>
        public VpnIpProtocolNumber Protocol_u32;

        /// <summary>
        /// The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
        /// </summary>
        public uint SrcPortStart_u32;

        /// <summary>
        /// The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
        /// </summary>
        public uint SrcPortEnd_u32;

        /// <summary>
        /// The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
        /// </summary>
        public uint DestPortStart_u32;

        /// <summary>
        /// The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
        /// </summary>
        public uint DestPortEnd_u32;

        /// <summary>
        /// Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
        /// </summary>
        public string SrcUsername_str;

        /// <summary>
        /// Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
        /// </summary>
        public string DestUsername_str;

        /// <summary>
        /// Specify true if you want to check the source MAC address.
        /// </summary>
        public bool CheckSrcMac_bool;

        /// <summary>
        /// Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
        /// </summary>
        public byte[] SrcMacAddress_bin;

        /// <summary>
        /// Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
        /// </summary>
        public byte[] SrcMacMask_bin;

        /// <summary>
        /// Specify true if you want to check the destination MAC address.
        /// </summary>
        public bool CheckDstMac_bool;

        /// <summary>
        /// Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
        /// </summary>
        public byte[] DstMacAddress_bin;

        /// <summary>
        /// Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
        /// </summary>
        public byte[] DstMacMask_bin;

        /// <summary>
        /// Specify true if you want to check the state of the TCP connection.
        /// </summary>
        public bool CheckTcpState_bool;

        /// <summary>
        /// Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets.
        /// </summary>
        public bool Established_bool;

        /// <summary>
        /// Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most.
        /// </summary>
        public uint Delay_u32;

        /// <summary>
        /// Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate.
        /// </summary>
        public uint Jitter_u32;

        /// <summary>
        /// Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate.
        /// </summary>
        public uint Loss_u32;

        /// <summary>
        /// The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address.
        /// </summary>
        public string RedirectUrl_str;
    }

    /// <summary>
    /// Add an item to Access List
    /// </summary>
    public class VpnRpcAddAccess
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Access list (Must be a single item)
        /// </summary>
        public VpnAccess[] AccessListSingle;
    }

    /// <summary>
    /// Add CA to HUB
    /// </summary>
    public class VpnRpcHubAddCA
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The body of the X.509 certificate
        /// </summary>
        public byte[] Cert_bin;
    }

    /// <summary>
    /// CRL entry
    /// </summary>
    public class VpnRpcCrl
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Key ID
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// CN, optional
        /// </summary>
        public string CommonName_utf;

        /// <summary>
        /// O, optional
        /// </summary>
        public string Organization_utf;

        /// <summary>
        /// OU, optional
        /// </summary>
        public string Unit_utf;

        /// <summary>
        /// C, optional
        /// </summary>
        public string Country_utf;

        /// <summary>
        /// ST, optional
        /// </summary>
        public string State_utf;

        /// <summary>
        /// L, optional
        /// </summary>
        public string Local_utf;

        /// <summary>
        /// Serial, optional
        /// </summary>
        public byte[] Serial_bin;

        /// <summary>
        /// MD5 Digest, optional
        /// </summary>
        public byte[] DigestMD5_bin;

        /// <summary>
        /// SHA1 Digest, optional
        /// </summary>
        public byte[] DigestSHA1_bin;
    }

    /// <summary>
    /// EtherIP key list entry
    /// </summary>
    public class VpnEtherIpId
    {
        /// <summary>
        /// Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules.
        /// </summary>
        public string Id_str;

        /// <summary>
        /// Specify the name of the Virtual Hub to connect.
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Specify the username to login to the destination Virtual Hub.
        /// </summary>
        public string UserName_str;

        /// <summary>
        /// Specify the password to login to the destination Virtual Hub.
        /// </summary>
        public string Password_str;
    }

    /// <summary>
    /// Layer-3 virtual interface
    /// </summary>
    public class VpnRpcL3If
    {
        /// <summary>
        /// L3 switch name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Virtual HUB name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// IP address
        /// </summary>
        public string IpAddress_ip;

        /// <summary>
        /// Subnet mask
        /// </summary>
        public string SubnetMask_ip;
    }

    /// <summary>
    /// Layer-3 switch
    /// </summary>
    public class VpnRpcL3Sw
    {
        /// <summary>
        /// Layer-3 Switch name
        /// </summary>
        public string Name_str;
    }

    /// <summary>
    /// Routing table
    /// </summary>
    public class VpnRpcL3Table
    {
        /// <summary>
        /// L3 switch name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Network address
        /// </summary>
        public string NetworkAddress_ip;

        /// <summary>
        /// Subnet mask
        /// </summary>
        public string SubnetMask_ip;

        /// <summary>
        /// Gateway address
        /// </summary>
        public string GatewayAddress_ip;

        /// <summary>
        /// Metric
        /// </summary>
        public uint Metric_u32;
    }

    /// <summary>
    /// Generic parameter to contain u32, u64, ascii_string and unicode string
    /// </summary>
    public class VpnRpcTest
    {
        /// <summary>
        /// A 32-bit integer field
        /// </summary>
        public uint IntValue_u32;

        /// <summary>
        /// A 64-bit integer field
        /// </summary>
        public ulong Int64Value_u64;

        /// <summary>
        /// An Ascii string field
        /// </summary>
        public string StrValue_str;

        /// <summary>
        /// An UTF-8 string field
        /// </summary>
        public string UniStrValue_utf;
    }

    /// <summary>
    /// Local Bridge list item
    /// </summary>
    public class VpnRpcLocalBridge
    {
        /// <summary>
        /// Physical Ethernet device name
        /// </summary>
        public string DeviceName_str;

        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubNameLB_str;

        /// <summary>
        /// Online flag
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// Running flag
        /// </summary>
        public bool Active_bool;

        /// <summary>
        /// Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions).
        /// </summary>
        public bool TapMode_bool;
    }

    /// <summary>
    /// Create, configure, and get the group
    /// </summary>
    public class VpnRpcSetGroup
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The group name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Optional real name (full name) of the group, allow using any Unicode characters
        /// </summary>
        public string Realname_utf;

        /// <summary>
        /// Optional, specify a description of the group
        /// </summary>
        public string Note_utf;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;

        /// <summary>
        /// The flag whether to use security policy
        /// </summary>
        public bool UsePolicy_bool;

        // ---- Start of Security policy ---
        /// <summary>
        /// Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
        /// </summary>
        [JsonProperty("policy:Access_bool")]
        public bool SecPol_Access_bool;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPFilter_bool")]
        public bool SecPol_DHCPFilter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPNoServer_bool")]
        public bool SecPol_DHCPNoServer_bool;

        /// <summary>
        /// Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
        /// </summary>
        [JsonProperty("policy:DHCPForce_bool")]
        public bool SecPol_DHCPForce_bool;

        /// <summary>
        /// Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoBridge_bool")]
        public bool SecPol_NoBridge_bool;

        /// <summary>
        /// Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoRouting_bool")]
        public bool SecPol_NoRouting_bool;

        /// <summary>
        /// Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckMac_bool")]
        public bool SecPol_CheckMac_bool;

        /// <summary>
        /// Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckIP_bool")]
        public bool SecPol_CheckIP_bool;

        /// <summary>
        /// Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:ArpDhcpOnly_bool")]
        public bool SecPol_ArpDhcpOnly_bool;

        /// <summary>
        /// Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
        /// </summary>
        [JsonProperty("policy:PrivacyFilter_bool")]
        public bool SecPol_PrivacyFilter_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
        /// </summary>
        [JsonProperty("policy:NoServer_bool")]
        public bool SecPol_NoServer_bool;

        /// <summary>
        /// Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
        /// </summary>
        [JsonProperty("policy:NoBroadcastLimiter_bool")]
        public bool SecPol_NoBroadcastLimiter_bool;

        /// <summary>
        /// Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MonitorPort_bool")]
        public bool SecPol_MonitorPort_bool;

        /// <summary>
        /// Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
        /// </summary>
        [JsonProperty("policy:MaxConnection_u32")]
        public uint SecPol_MaxConnection_u32;

        /// <summary>
        /// Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
        /// </summary>
        [JsonProperty("policy:TimeOut_u32")]
        public uint SecPol_TimeOut_u32;

        /// <summary>
        /// Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
        /// </summary>
        [JsonProperty("policy:MaxMac_u32")]
        public uint SecPol_MaxMac_u32;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIP_u32")]
        public uint SecPol_MaxIP_u32;

        /// <summary>
        /// Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxUpload_u32")]
        public uint SecPol_MaxUpload_u32;

        /// <summary>
        /// Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxDownload_u32")]
        public uint SecPol_MaxDownload_u32;

        /// <summary>
        /// Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
        /// </summary>
        [JsonProperty("policy:FixPassword_bool")]
        public bool SecPol_FixPassword_bool;

        /// <summary>
        /// Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
        /// </summary>
        [JsonProperty("policy:MultiLogins_u32")]
        public uint SecPol_MultiLogins_u32;

        /// <summary>
        /// Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
        /// </summary>
        [JsonProperty("policy:NoQoS_bool")]
        public bool SecPol_NoQoS_bool;

        /// <summary>
        /// Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
        /// </summary>
        [JsonProperty("policy:RSandRAFilter_bool")]
        public bool SecPol_RSandRAFilter_bool;

        /// <summary>
        /// Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
        /// </summary>
        [JsonProperty("policy:RAFilter_bool")]
        public bool SecPol_RAFilter_bool;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPv6Filter_bool")]
        public bool SecPol_DHCPv6Filter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPv6NoServer_bool")]
        public bool SecPol_DHCPv6NoServer_bool;

        /// <summary>
        /// Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoRoutingV6_bool")]
        public bool SecPol_NoRoutingV6_bool;

        /// <summary>
        /// Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckIPv6_bool")]
        public bool SecPol_CheckIPv6_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
        /// </summary>
        [JsonProperty("policy:NoServerV6_bool")]
        public bool SecPol_NoServerV6_bool;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIPv6_u32")]
        public uint SecPol_MaxIPv6_u32;

        /// <summary>
        /// Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
        /// </summary>
        [JsonProperty("policy:NoSavePassword_bool")]
        public bool SecPol_NoSavePassword_bool;

        /// <summary>
        /// Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
        /// </summary>
        [JsonProperty("policy:AutoDisconnect_u32")]
        public uint SecPol_AutoDisconnect_u32;

        /// <summary>
        /// Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv4_bool")]
        public bool SecPol_FilterIPv4_bool;

        /// <summary>
        /// Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv6_bool")]
        public bool SecPol_FilterIPv6_bool;

        /// <summary>
        /// Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
        /// </summary>
        [JsonProperty("policy:FilterNonIP_bool")]
        public bool SecPol_FilterNonIP_bool;

        /// <summary>
        /// Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
        /// </summary>
        [JsonProperty("policy:NoIPv6DefaultRouterInRA_bool")]
        public bool SecPol_NoIPv6DefaultRouterInRA_bool;

        /// <summary>
        /// Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
        /// </summary>
        [JsonProperty("policy:NoIPv6DefaultRouterInRAWhenIPv6_bool")]
        public bool SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool;

        /// <summary>
        /// Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
        /// </summary>
        [JsonProperty("policy:VLanId_u32")]
        public uint SecPol_VLanId_u32;

        /// <summary>
        /// Security policy: Whether version 3.0 (must be true)
        /// </summary>
        [JsonProperty("policy:Ver3_bool")]
        public bool SecPol_Ver3_bool = true;
        // ---- End of Security policy ---
    }

    /// <summary>
    /// Hub types
    /// </summary>
    public enum VpnRpcHubType
    {
        /// <summary>
        /// Stand-alone HUB
        /// </summary>
        Standalone = 0,

        /// <summary>
        /// Static HUB
        /// </summary>
        FarmStatic = 1,

        /// <summary>
        /// Dynamic HUB
        /// </summary>
        FarmDynamic = 2,
    }

    /// <summary>
    /// Create a HUB
    /// </summary>
    public class VpnRpcCreateHub
    {
        /// <summary>
        /// Specify the name of the Virtual Hub to create / update.
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password.
        /// </summary>
        public string AdminPasswordPlainText_str;

        /// <summary>
        /// Online flag
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// Maximum number of VPN sessions
        /// </summary>
        public uint MaxSession_u32;

        /// <summary>
        /// No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server.
        /// </summary>
        public bool NoEnum_bool;

        /// <summary>
        /// Type of the Virtual Hub (Valid only for Clustered VPN Servers)
        /// </summary>
        public VpnRpcHubType HubType_u32;
    }

    public enum VpnRpcClientAuthType
    {
        /// <summary>
        /// Anonymous authentication
        /// </summary>
        Anonymous = 0,

        /// <summary>
        /// SHA-0 hashed password authentication
        /// </summary>
        SHA0_Hashed_Password = 1,

        /// <summary>
        /// Plain password authentication
        /// </summary>
        PlainPassword = 2,

        /// <summary>
        /// Certificate authentication
        /// </summary>
        Cert = 3,
    }

    /// <summary>
    /// Create and set of link
    /// </summary>
    public class VpnRpcCreateLink
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_Ex_str;

        /// <summary>
        /// Online flag
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// The flag to enable validation for the server certificate
        /// </summary>
        public bool CheckServerCert_bool;

        /// <summary>
        /// The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true.
        /// </summary>
        public byte[] ServerCert_bin;

        // ---- Start of Client Option Parameters ---
        /// <summary>
        /// Client Option Parameters: Specify the name of the Cascade Connection
        /// </summary>
        [JsonProperty("AccountName_utf")]
        public string ClientOption_AccountName_utf;

        /// <summary>
        /// Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address.
        /// </summary>
        [JsonProperty("Hostname_str")]
        public string ClientOption_Hostname_str;

        /// <summary>
        /// Client Option Parameters: Specify the port number of the destination VPN Server.
        /// </summary>
        [JsonProperty("Port_u32")]
        public uint ClientOption_Port_u32;

        /// <summary>
        /// Client Option Parameters: The type of the proxy server
        /// </summary>
        [JsonProperty("ProxyType_u32")]
        public VpnRpcProxyType ClientOption_ProxyType_u32;

        /// <summary>
        /// Client Option Parameters: The hostname or IP address of the proxy server name
        /// </summary>
        [JsonProperty("ProxyName_str")]
        public string ClientOption_ProxyName_str;

        /// <summary>
        /// Client Option Parameters: The port number of the proxy server
        /// </summary>
        [JsonProperty("ProxyPort_u32")]
        public uint ClientOption_ProxyPort_u32;

        /// <summary>
        /// Client Option Parameters: The username to connect to the proxy server
        /// </summary>
        [JsonProperty("ProxyUsername_str")]
        public string ClientOption_ProxyUsername_str;

        /// <summary>
        /// Client Option Parameters: The password to connect to the proxy server
        /// </summary>
        [JsonProperty("ProxyPassword_str")]
        public string ClientOption_ProxyPassword_str;

        /// <summary>
        /// Client Option Parameters: The Virtual Hub on the destination VPN Server
        /// </summary>
        [JsonProperty("HubName_str")]
        public string ClientOption_HubName_str;

        /// <summary>
        /// Client Option Parameters: Number of TCP Connections to Use in VPN Communication
        /// </summary>
        [JsonProperty("MaxConnection_u32")]
        public uint ClientOption_MaxConnection_u32;

        /// <summary>
        /// Client Option Parameters: The flag to enable the encryption on the communication
        /// </summary>
        [JsonProperty("UseEncrypt_bool")]
        public bool ClientOption_UseEncrypt_bool;

        /// <summary>
        /// Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection
        /// </summary>
        [JsonProperty("UseCompress_bool")]
        public bool ClientOption_UseCompress_bool;

        /// <summary>
        /// Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction.
        /// </summary>
        [JsonProperty("HalfConnection_bool")]
        public bool ClientOption_HalfConnection_bool;

        /// <summary>
        /// Client Option Parameters: Connection attempt interval when additional connection will be established
        /// </summary>
        [JsonProperty("AdditionalConnectionInterval_u32")]
        public uint ClientOption_AdditionalConnectionInterval_u32;

        /// <summary>
        /// Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive)
        /// </summary>
        [JsonProperty("ConnectionDisconnectSpan_u32")]
        public uint ClientOption_ConnectionDisconnectSpan_u32;

        /// <summary>
        /// Client Option Parameters: Disable QoS Control Function if the value is true
        /// </summary>
        [JsonProperty("DisableQoS_bool")]
        public bool ClientOption_DisableQoS_bool;

        /// <summary>
        /// Client Option Parameters: Do not use TLS 1.x of the value is true
        /// </summary>
        [JsonProperty("NoTls1_bool")]
        public bool ClientOption_NoTls1_bool;

        /// <summary>
        /// Client Option Parameters: Do not use UDP acceleration mode if the value is true
        /// </summary>
        [JsonProperty("NoUdpAcceleration_bool")]
        public bool ClientOption_NoUdpAcceleration_bool;
        // ---- End of Client Option ---

        // ---- Start of Client Auth Parameters ---
        /// <summary>
        /// Authentication type
        /// </summary>
        [JsonProperty("AuthType_u32")]
        public VpnRpcClientAuthType ClientAuth_AuthType_u32;

        /// <summary>
        /// User name
        /// </summary>
        [JsonProperty("Username_str")]
        public string ClientAuth_Username_str;

        /// <summary>
        /// SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(UpperCase(username_ascii_string) + password_ascii_string).
        /// </summary>
        [JsonProperty("HashedPassword_bin")]
        public byte[] ClientAuth_HashedPassword_bin;

        /// <summary>
        /// Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2).
        /// </summary>
        [JsonProperty("PlainPassword_str")]
        public string ClientAuth_PlainPassword_str;

        /// <summary>
        /// Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
        /// </summary>
        [JsonProperty("ClientX_bin")]
        public byte[] ClientAuth_ClientX_bin;

        /// <summary>
        /// Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
        /// </summary>
        [JsonProperty("ClientK_bin")]
        public byte[] ClientAuth_ClientK_bin;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPFilter_bool")]
        public bool SecPol_DHCPFilter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPNoServer_bool")]
        public bool SecPol_DHCPNoServer_bool;

        /// <summary>
        /// Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
        /// </summary>
        [JsonProperty("policy:DHCPForce_bool")]
        public bool SecPol_DHCPForce_bool;

        /// <summary>
        /// Security policy: Prohibit the duplicate MAC address
        /// </summary>
        /// Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        public bool SecPol_CheckMac_bool;

        /// <summary>
        /// Security policy: Prohibit a duplicate IP address (IPv4)
        /// </summary>
        /// Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        public bool SecPol_CheckIP_bool;

        /// <summary>
        /// Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:ArpDhcpOnly_bool")]
        public bool SecPol_ArpDhcpOnly_bool;

        /// <summary>
        /// Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
        /// </summary>
        [JsonProperty("policy:PrivacyFilter_bool")]
        public bool SecPol_PrivacyFilter_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
        /// </summary>
        [JsonProperty("policy:NoServer_bool")]
        public bool SecPol_NoServer_bool;

        /// <summary>
        /// Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
        /// </summary>
        [JsonProperty("policy:NoBroadcastLimiter_bool")]
        public bool SecPol_NoBroadcastLimiter_bool;

        /// <summary>
        /// Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
        /// </summary>
        [JsonProperty("policy:MaxMac_u32")]
        public uint SecPol_MaxMac_u32;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIP_u32")]
        public uint SecPol_MaxIP_u32;

        /// <summary>
        /// Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxUpload_u32")]
        public uint SecPol_MaxUpload_u32;

        /// <summary>
        /// Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxDownload_u32")]
        public uint SecPol_MaxDownload_u32;

        /// <summary>
        /// Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
        /// </summary>
        [JsonProperty("policy:RSandRAFilter_bool")]
        public bool SecPol_RSandRAFilter_bool;

        /// <summary>
        /// Security policy: Filter the router advertisement packet (IPv6)
        /// </summary>
        /// Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
        public bool SecPol_RAFilter_bool;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPv6Filter_bool")]
        public bool SecPol_DHCPv6Filter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPv6NoServer_bool")]
        public bool SecPol_DHCPv6NoServer_bool;

        /// <summary>
        /// Security policy: Prohibit the duplicate IP address (IPv6)
        /// </summary>
        /// Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        public bool SecPol_CheckIPv6_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
        /// </summary>
        [JsonProperty("policy:NoServerV6_bool")]
        public bool SecPol_NoServerV6_bool;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIPv6_u32")]
        public uint SecPol_MaxIPv6_u32;

        /// <summary>
        /// Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv4_bool")]
        public bool SecPol_FilterIPv4_bool;

        /// <summary>
        /// Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv6_bool")]
        public bool SecPol_FilterIPv6_bool;

        /// <summary>
        /// Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
        /// </summary>
        [JsonProperty("policy:FilterNonIP_bool")]
        public bool SecPol_FilterNonIP_bool;

        /// <summary>
        /// Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
        /// </summary>
        [JsonProperty("policy:NoIPv6DefaultRouterInRA_bool")]
        public bool SecPol_NoIPv6DefaultRouterInRA_bool;

        /// <summary>
        /// Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
        /// </summary>
        [JsonProperty("policy:VLanId_u32")]
        public uint SecPol_VLanId_u32;

        /// <summary>
        /// Security policy: Whether version 3.0 (must be true)
        /// </summary>
        [JsonProperty("policy:Ver3_bool")]
        public bool SecPol_Ver3_bool = true;
        // ---- End of Security policy ---
    }

    /// <summary>
    /// Listener
    /// </summary>
    public class VpnRpcListener
    {
        /// <summary>
        /// Port number (Range: 1 - 65535)
        /// </summary>
        public uint Port_u32;

        /// <summary>
        /// Active state
        /// </summary>
        public bool Enable_bool;
    }

    /// <summary>
    /// User authentication type (server side)
    /// </summary>
    public enum VpnRpcUserAuthType
    {
        /// <summary>
        /// Anonymous authentication
        /// </summary>
        Anonymous = 0,

        /// <summary>
        /// Password authentication
        /// </summary>
        Password = 1,

        /// <summary>
        /// User certificate authentication
        /// </summary>
        UserCert = 2,

        /// <summary>
        /// Root certificate which is issued by trusted Certificate Authority
        /// </summary>
        RootCert = 3,

        /// <summary>
        /// Radius authentication
        /// </summary>
        Radius = 4,

        /// <summary>
        /// Windows NT authentication
        /// </summary>
        NTDomain = 5,
    }

    /// <summary>
    /// Create, configure, and get the user
    /// </summary>
    public class VpnRpcSetUser
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Specify the user name of the user
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Assigned group name for the user
        /// </summary>
        public string GroupName_str;

        /// <summary>
        /// Optional real name (full name) of the user, allow using any Unicode characters
        /// </summary>
        public string Realname_utf;

        /// <summary>
        /// Optional User Description
        /// </summary>
        public string Note_utf;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Last modified date and time
        /// </summary>
        public DateTime UpdatedTime_dt;

        /// <summary>
        /// Expiration date and time
        /// </summary>
        public DateTime ExpireTime_dt;

        /// <summary>
        /// Authentication method of the user
        /// </summary>
        public VpnRpcUserAuthType AuthType_u32;

        /// <summary>
        /// User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations.
        /// </summary>
        public string Auth_Password_str;

        /// <summary>
        /// User certificate, valid only if AuthType_u32 == UserCert(2).
        /// </summary>
        [JsonProperty("UserX_bin")]
        public byte[] Auth_UserCert_CertData;

        /// <summary>
        /// Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3).
        /// </summary>
        [JsonProperty("Serial_bin")]
        public byte[] Auth_RootCert_Serial;

        /// <summary>
        /// Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3).
        /// </summary>
        [JsonProperty("CommonName_utf")]
        public string Auth_RootCert_CommonName;

        /// <summary>
        /// Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4).
        /// </summary>
        [JsonProperty("RadiusUsername_utf")]
        public string Auth_Radius_RadiusUsername;

        /// <summary>
        /// Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5).
        /// </summary>
        [JsonProperty("NtUsername_utf")]
        public string Auth_NT_NTUsername;

        /// <summary>
        /// Number of total logins of the user
        /// </summary>
        public uint NumLogin_u32;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;

        /// <summary>
        /// The flag whether to use security policy
        /// </summary>
        public bool UsePolicy_bool;

        // ---- Start of Security policy ---
        /// <summary>
        /// Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
        /// </summary>
        [JsonProperty("policy:Access_bool")]
        public bool SecPol_Access_bool;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPFilter_bool")]
        public bool SecPol_DHCPFilter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPNoServer_bool")]
        public bool SecPol_DHCPNoServer_bool;

        /// <summary>
        /// Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
        /// </summary>
        [JsonProperty("policy:DHCPForce_bool")]
        public bool SecPol_DHCPForce_bool;

        /// <summary>
        /// Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoBridge_bool")]
        public bool SecPol_NoBridge_bool;

        /// <summary>
        /// Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoRouting_bool")]
        public bool SecPol_NoRouting_bool;

        /// <summary>
        /// Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckMac_bool")]
        public bool SecPol_CheckMac_bool;

        /// <summary>
        /// Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckIP_bool")]
        public bool SecPol_CheckIP_bool;

        /// <summary>
        /// Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:ArpDhcpOnly_bool")]
        public bool SecPol_ArpDhcpOnly_bool;

        /// <summary>
        /// Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
        /// </summary>
        [JsonProperty("policy:PrivacyFilter_bool")]
        public bool SecPol_PrivacyFilter_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
        /// </summary>
        [JsonProperty("policy:NoServer_bool")]
        public bool SecPol_NoServer_bool;

        /// <summary>
        /// Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
        /// </summary>
        [JsonProperty("policy:NoBroadcastLimiter_bool")]
        public bool SecPol_NoBroadcastLimiter_bool;

        /// <summary>
        /// Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MonitorPort_bool")]
        public bool SecPol_MonitorPort_bool;

        /// <summary>
        /// Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
        /// </summary>
        [JsonProperty("policy:MaxConnection_u32")]
        public uint SecPol_MaxConnection_u32;

        /// <summary>
        /// Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
        /// </summary>
        [JsonProperty("policy:TimeOut_u32")]
        public uint SecPol_TimeOut_u32;

        /// <summary>
        /// Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
        /// </summary>
        [JsonProperty("policy:MaxMac_u32")]
        public uint SecPol_MaxMac_u32;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIP_u32")]
        public uint SecPol_MaxIP_u32;

        /// <summary>
        /// Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxUpload_u32")]
        public uint SecPol_MaxUpload_u32;

        /// <summary>
        /// Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
        /// </summary>
        [JsonProperty("policy:MaxDownload_u32")]
        public uint SecPol_MaxDownload_u32;

        /// <summary>
        /// Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
        /// </summary>
        [JsonProperty("policy:FixPassword_bool")]
        public bool SecPol_FixPassword_bool;

        /// <summary>
        /// Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
        /// </summary>
        [JsonProperty("policy:MultiLogins_u32")]
        public uint SecPol_MultiLogins_u32;

        /// <summary>
        /// Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
        /// </summary>
        [JsonProperty("policy:NoQoS_bool")]
        public bool SecPol_NoQoS_bool;

        /// <summary>
        /// Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
        /// </summary>
        [JsonProperty("policy:RSandRAFilter_bool")]
        public bool SecPol_RSandRAFilter_bool;

        /// <summary>
        /// Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
        /// </summary>
        [JsonProperty("policy:RAFilter_bool")]
        public bool SecPol_RAFilter_bool;

        /// <summary>
        /// Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:DHCPv6Filter_bool")]
        public bool SecPol_DHCPv6Filter_bool;

        /// <summary>
        /// Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
        /// </summary>
        [JsonProperty("policy:DHCPv6NoServer_bool")]
        public bool SecPol_DHCPv6NoServer_bool;

        /// <summary>
        /// Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
        /// </summary>
        [JsonProperty("policy:NoRoutingV6_bool")]
        public bool SecPol_NoRoutingV6_bool;

        /// <summary>
        /// Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
        /// </summary>
        [JsonProperty("policy:CheckIPv6_bool")]
        public bool SecPol_CheckIPv6_bool;

        /// <summary>
        /// Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
        /// </summary>
        [JsonProperty("policy:NoServerV6_bool")]
        public bool SecPol_NoServerV6_bool;

        /// <summary>
        /// Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
        /// </summary>
        [JsonProperty("policy:MaxIPv6_u32")]
        public uint SecPol_MaxIPv6_u32;

        /// <summary>
        /// Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
        /// </summary>
        [JsonProperty("policy:NoSavePassword_bool")]
        public bool SecPol_NoSavePassword_bool;

        /// <summary>
        /// Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
        /// </summary>
        [JsonProperty("policy:AutoDisconnect_u32")]
        public uint SecPol_AutoDisconnect_u32;

        /// <summary>
        /// Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv4_bool")]
        public bool SecPol_FilterIPv4_bool;

        /// <summary>
        /// Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
        /// </summary>
        [JsonProperty("policy:FilterIPv6_bool")]
        public bool SecPol_FilterIPv6_bool;

        /// <summary>
        /// Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
        /// </summary>
        [JsonProperty("policy:FilterNonIP_bool")]
        public bool SecPol_FilterNonIP_bool;

        /// <summary>
        /// Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
        /// </summary>
        [JsonProperty("policy:NoIPv6DefaultRouterInRA_bool")]
        public bool SecPol_NoIPv6DefaultRouterInRA_bool;

        /// <summary>
        /// Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
        /// </summary>
        [JsonProperty("policy:NoIPv6DefaultRouterInRAWhenIPv6_bool")]
        public bool SecPol_NoIPv6DefaultRouterInRAWhenIPv6_bool;

        /// <summary>
        /// Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
        /// </summary>
        [JsonProperty("policy:VLanId_u32")]
        public uint SecPol_VLanId_u32;

        /// <summary>
        /// Security policy: Whether version 3.0 (must be true)
        /// </summary>
        [JsonProperty("policy:Ver3_bool")]
        public bool SecPol_Ver3_bool = true;
        // ---- End of Security policy ---
    }

    /// <summary>
    /// Delete the access list
    /// </summary>
    public class VpnRpcDeleteAccess
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;
    }

    /// <summary>
    /// Delete the CA of HUB
    /// </summary>
    public class VpnRpcHubDeleteCA
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Certificate key id to be deleted
        /// </summary>
        public uint Key_u32;
    }

    /// <summary>
    /// Deleting a user or group
    /// </summary>
    public class VpnRpcDeleteUser
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// User or group name
        /// </summary>
        public string Name_str;
    }

    /// <summary>
    /// Delete the HUB
    /// </summary>
    public class VpnRpcDeleteHub
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;
    }

    /// <summary>
    /// Delete the table
    /// </summary>
    public class VpnRpcDeleteTable
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Key ID
        /// </summary>
        public uint Key_u32;
    }

    /// <summary>
    /// Specify the Link
    /// </summary>
    public class VpnRpcLink
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The name of the cascade connection
        /// </summary>
        public string AccountName_utf;
    }

    /// <summary>
    /// Disconnect the session
    /// </summary>
    public class VpnRpcDeleteSession
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Session name
        /// </summary>
        public string Name_str;
    }

    /// <summary>
    /// Specify the HUB
    /// </summary>
    public class VpnRpcHub
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;
    }

    /// <summary>
    /// Disconnect a connection
    /// </summary>
    public class VpnRpcDisconnectConnection
    {
        /// <summary>
        /// Connection name
        /// </summary>
        public string Name_str;
    }

    /// <summary>
    /// Enumeration of the access list
    /// </summary>
    public class VpnRpcEnumAccessList
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Access list
        /// </summary>
        public VpnAccess[] AccessList;
    }

    /// <summary>
    /// CA enumeration items of HUB
    /// </summary>
    public class VpnRpcHubEnumCAItem
    {
        /// <summary>
        /// The key id of the item
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// Subject
        /// </summary>
        public string SubjectName_utf;

        /// <summary>
        /// Issuer
        /// </summary>
        public string IssuerName_utf;

        /// <summary>
        /// Expiration date
        /// </summary>
        public DateTime Expires_dt;
    }

    /// <summary>
    /// CA enumeration of HUB
    /// </summary>
    public class VpnRpcHubEnumCA
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The list of CA
        /// </summary>
        public VpnRpcHubEnumCAItem[] CAList;
    }

    /// <summary>
    /// Type of connection
    /// </summary>
    public enum VpnRpcConnectionType
    {
        /// <summary>
        ///  VPN Client
        /// </summary>
        Client = 0,

        /// <summary>
        /// During initialization
        /// </summary>
        Init = 1,

        /// <summary>
        /// Login connection
        /// </summary>
        Login = 2,

        /// <summary>
        /// Additional connection
        /// </summary>
        Additional = 3,

        /// <summary>
        /// RPC for server farm
        /// </summary>
        FarmRpc = 4,

        /// <summary>
        /// RPC for Management
        /// </summary>
        AdminRpc = 5,

        /// <summary>
        /// HUB enumeration
        /// </summary>
        EnumHub = 6,

        /// <summary>
        /// Password change
        /// </summary>
        Password = 7,

        /// <summary>
        /// SSTP
        /// </summary>
        SSTP = 8,

        /// <summary>
        /// OpenVPN
        /// </summary>
        OpenVPN = 9,
    }

    /// <summary>
    /// Connection enumeration items
    /// </summary>
    public class VpnRpcEnumConnectionItem
    {
        /// <summary>
        /// Connection name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Port number
        /// </summary>
        public uint Port_u32;

        /// <summary>
        /// Connected time
        /// </summary>
        public DateTime ConnectedTime_dt;

        /// <summary>
        /// Connection type
        /// </summary>
        public VpnRpcConnectionType Type_u32;
    }

    /// <summary>
    /// Connection enumeration
    /// </summary>
    public class VpnRpcEnumConnection
    {
        /// <summary>
        /// Number of connections
        /// </summary>
        public uint NumConnection_u32;

        /// <summary>
        /// Connection list
        /// </summary>
        public VpnRpcEnumConnectionItem[] ConnectionList;
    }

    /// <summary>
    /// Enum CRL Item
    /// </summary>
    public class VpnRpcEnumCrlItem
    {
        /// <summary>
        /// Key ID
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// The contents of the CRL item
        /// </summary>
        public string CrlInfo_utf;
    }

    /// <summary>
    /// Enum CRL
    ///</summary>
    public class VpnRpcEnumCrl
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// CRL list
        /// </summary>
        public VpnRpcEnumCrlItem[] CRLList;
    }

    /// <summary>
    /// RPC_ENUM_DHCP_ITEM
    /// </summary>
    public class VpnRpcEnumDhcpItem
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// Lease time
        /// </summary>
        public DateTime LeasedTime_dt;

        /// <summary>
        /// Expiration date
        /// </summary>
        public DateTime ExpireTime_dt;

        /// <summary>
        /// MAC address
        /// </summary>
        public byte[] MacAddress_bin;

        /// <summary>
        /// IP address
        /// </summary>
        public string IpAddress_ip;

        /// <summary>
        /// Subnet mask
        /// </summary>
        public uint Mask_u32;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;
    }

    /// <summary>
    /// RPC_ENUM_DHCP
    /// </summary>
    public class VpnRpcEnumDhcp
    {
        /// <summary>
        /// Virtual Hub Name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// DHCP Item
        /// </summary>
        public VpnRpcEnumDhcpItem[] DhcpTable;
    }

    /// <summary>
    /// EtherIP setting list
    /// </summary>
    public class VpnRpcEnumEtherIpId
    {
        /// <summary>
        /// Setting list
        /// </summary>
        public VpnEtherIpId[] Settings;
    }

    /// <summary>
    /// Ethernet Network Adapters list item
    /// </summary>
    public class VpnRpcEnumEthItem
    {
        /// <summary>
        /// Device name
        /// </summary>
        public string DeviceName_str;

        /// <summary>
        /// Network connection name (description)
        /// </summary>
        public string NetworkConnectionName_utf;
    }

    /// <summary>
    /// Ethernet Network Adapters list
    /// </summary>
    public class VpnRpcEnumEth
    {
        /// <summary>
        /// Ethernet Network Adapters list
        /// </summary>
        public VpnRpcEnumEthItem[] EthList;
    }

    /// <summary>
    /// Server farm members enumeration items
    /// </summary>
    public class VpnRpcEnumFarmItem
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// Controller
        /// </summary>
        public bool Controller_bool;

        /// <summary>
        /// Connection time
        /// </summary>
        public DateTime ConnectedTime_dt;

        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// Point
        /// </summary>
        public uint Point_u32;

        /// <summary>
        /// Number of sessions
        /// </summary>
        public uint NumSessions_u32;

        /// <summary>
        /// Number of TCP connections
        /// </summary>
        public uint NumTcpConnections_u32;

        /// <summary>
        /// Number of HUBs
        /// </summary>
        public uint NumHubs_u32;

        /// <summary>
        /// Number of assigned client licenses
        /// </summary>
        public uint AssignedClientLicense_u32;

        /// <summary>
        /// Number of assigned bridge licenses
        /// </summary>
        public uint AssignedBridgeLicense_u32;
    }

    /// <summary>
    /// Server farm member enumeration 
    /// </summary>
    public class VpnRpcEnumFarm
    {
        /// <summary>
        /// Number of Cluster Members
        /// </summary>
        public uint NumFarm_u32;

        /// <summary>
        /// Cluster Members list
        /// </summary>
        public VpnRpcEnumFarmItem[] FarmMemberList;
    }

    /// <summary>
    /// Enumeration items in the group
    /// </summary>
    public class VpnRpcEnumGroupItem
    {
        /// <summary>
        /// User name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Real name
        /// </summary>
        public string Realname_utf;

        /// <summary>
        /// Note
        /// </summary>
        public string Note_utf;

        /// <summary>
        /// Number of users
        /// </summary>
        public uint NumUsers_u32;

        /// <summary>
        /// Access denied
        /// </summary>
        public bool DenyAccess_bool;
    }

    /// <summary>
    /// Group enumeration
    /// </summary>
    public class VpnRpcEnumGroup
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Group list
        /// </summary>
        public VpnRpcEnumGroupItem[] GroupList;
    }

    /// <summary>
    /// Enumeration items of HUB
    /// </summary>
    public class VpnRpcEnumHubItem
    {
        /// <summary>
        /// The name of the Virtual Hub
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Online state
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// Type of HUB (Valid only for Clustered VPN Servers)
        /// </summary>
        public VpnRpcHubType HubType_u32;

        /// <summary>
        /// Number of users
        /// </summary>
        public uint NumUsers_u32;

        /// <summary>
        /// Number of registered groups
        /// </summary>
        public uint NumGroups_u32;

        /// <summary>
        /// Number of registered sessions
        /// </summary>
        public uint NumSessions_u32;

        /// <summary>
        /// Number of current MAC table entries
        /// </summary>
        public uint NumMacTables_u32;

        /// <summary>
        /// Number of current IP table entries
        /// </summary>
        public uint NumIpTables_u32;

        /// <summary>
        /// Last communication date and time
        /// </summary>
        public DateTime LastCommTime_dt;

        /// <summary>
        /// Last login date and time
        /// </summary>
        public DateTime LastLoginTime_dt;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Number of accumulated logins
        /// </summary>
        public uint NumLogin_u32;

        /// <summary>
        /// Whether the traffic information is provided
        /// </summary>
        public bool IsTrafficFilled_bool;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Ex.Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;
    }

    /// <summary>
    /// Enumeration of HUB
    /// </summary>
    public class VpnRpcEnumHub
    {
        /// <summary>
        /// Number of Virtual Hubs
        /// </summary>
        public uint NumHub_u32;

        /// <summary>
        /// Virtual Hubs
        /// </summary>
        public VpnRpcEnumHubItem[] HubList;
    }

    /// <summary>
    /// Enumeration items of IP table
    /// </summary>
    public class VpnRpcEnumIpTableItem
    {
        /// <summary>
        /// Key ID
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// Session name
        /// </summary>
        public string SessionName_str;

        /// <summary>
        /// IP address
        /// </summary>
        public string IpAddress_ip;

        /// <summary>
        /// Assigned by the DHCP
        /// </summary>
        public bool DhcpAllocated_bool;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Updating date
        /// </summary>
        public DateTime UpdatedTime_dt;

        /// <summary>
        /// Remote items
        /// </summary>
        public bool RemoteItem_bool;

        /// <summary>
        /// Remote host name
        /// </summary>
        public string RemoteHostname_str;
    }

    /// <summary>
    /// Enumeration of IP table
    /// </summary>
    public class VpnRpcEnumIpTable
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// MAC table
        /// </summary>
        public VpnRpcEnumIpTableItem[] IpTable;
    }

    /// <summary>
    /// Layer-3 interface enumeration
    /// </summary>
    public class VpnRpcEnumL3If
    {
        /// <summary>
        /// Layer-3 switch name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Layer-3 interface list
        /// </summary>
        public VpnRpcL3If[] L3IFList;
    }

    /// <summary>
    /// Layer-3 switch enumeration item
    /// </summary>
    public class VpnRpcEnumL3SwItem
    {
        /// <summary>
        /// Name of the layer-3 switch
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Number of layer-3 switch virtual interfaces
        /// </summary>
        public uint NumInterfaces_u32;

        /// <summary>
        /// Number of routing tables
        /// </summary>
        public uint NumTables_u32;

        /// <summary>
        /// Activated flag
        /// </summary>
        public bool Active_bool;

        /// <summary>
        /// Online flag
        /// </summary>
        public bool Online_bool;
    }

    /// <summary>
    /// Layer-3 switch enumeration
    /// </summary>
    public class VpnRpcEnumL3Sw
    {
        /// <summary>
        /// Layer-3 switch list
        /// </summary>
        public VpnRpcEnumL3SwItem[] L3SWList;
    }

    /// <summary>
    /// Routing table enumeration
    /// </summary>
    public class VpnRpcEnumL3Table
    {
        /// <summary>
        /// L3 switch name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Routing table item list
        /// </summary>
        public VpnRpcL3Table[] L3Table;
    }

    /// <summary>
    /// Cascade Connection Enumeration
    /// </summary>
    public class VpnRpcEnumLinkItem
    {
        /// <summary>
        /// The name of cascade connection
        /// </summary>
        public string AccountName_utf;

        /// <summary>
        /// Online flag
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// The flag indicates whether the cascade connection is established
        /// </summary>
        public bool Connected_bool;

        /// <summary>
        /// The error last occurred if the cascade connection is in the fail state
        /// </summary>
        public uint LastError_u32;

        /// <summary>
        /// Connection completion time
        /// </summary>
        public DateTime ConnectedTime_dt;

        /// <summary>
        /// Host name of the destination VPN server
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string TargetHubName_str;
    }

    /// <summary>
    /// Enumeration of the link
    /// </summary>
    public class VpnRpcEnumLink
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Number of cascade connections
        /// </summary>
        public uint NumLink_u32;

        /// <summary>
        /// The list of cascade connections
        /// </summary>
        public VpnRpcEnumLinkItem[] LinkList;
    }

    /// <summary>
    /// List of listeners item
    /// </summary>
    public class VpnRpcListenerListItem
    {
        /// <summary>
        /// TCP port number (range: 1 - 65535)
        /// </summary>
        public uint Ports_u32;

        /// <summary>
        /// Active state
        /// </summary>
        public bool Enables_bool;

        /// <summary>
        /// The flag to indicate if the error occurred on the listener port
        /// </summary>
        public bool Errors_bool;
    }

    /// <summary>
    /// List of listeners
    /// </summary>
    public class VpnRpcListenerList
    {
        /// <summary>
        /// List of listener items
        /// </summary>
        public VpnRpcListenerListItem[] ListenerList;
    }

    /// <summary>
    /// Local Bridge enumeration
    /// </summary>
    public class VpnRpcEnumLocalBridge
    {
        /// <summary>
        /// Local Bridge list
        /// </summary>
        public VpnRpcLocalBridge[] LocalBridgeList;
    }

    /// <summary>
    /// Log file enumeration
    /// </summary>
    public class VpnRpcEnumLogFileItem
    {
        /// <summary>
        /// Server name
        /// </summary>
        public string ServerName_str;

        /// <summary>
        /// File path
        /// </summary>
        public string FilePath_str;

        /// <summary>
        /// File size
        /// </summary>
        public uint FileSize_u32;

        /// <summary>
        /// Last write date
        /// </summary>
        public DateTime UpdatedTime_dt;
    }

    /// <summary>
    /// Log file enumeration
    ///</summary>
    public class VpnRpcEnumLogFile
    {
        /// <summary>
        /// Log file list
        /// </summary>
        public VpnRpcEnumLogFileItem[] LogFiles;
    }

    /// <summary>
    /// Enumeration items of the MAC table
    /// </summary>
    public class VpnRpcEnumMacTableItem
    {
        /// <summary>
        /// Key ID
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// Session name
        /// </summary>
        public string SessionName_str;

        /// <summary>
        /// MAC address
        /// </summary>
        public byte[] MacAddress_bin;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Updating date
        /// </summary>
        public DateTime UpdatedTime_dt;

        /// <summary>
        /// Remote items
        /// </summary>
        public bool RemoteItem_bool;

        /// <summary>
        /// Remote host name
        /// </summary>
        public string RemoteHostname_str;

        /// <summary>
        /// VLAN ID
        /// </summary>
        public uint VlanId_u32;
    }

    /// <summary>
    /// Enumeration of the MAC table
    /// </summary>
    public class VpnRpcEnumMacTable
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// MAC table
        /// </summary>
        public VpnRpcEnumMacTableItem[] MacTable;
    }

    /// <summary>
    /// NAT Entry Protocol Number
    /// </summary>
    public enum VpnRpcNatProtocol
    {
        /// <summary>
        ///  TCP
        /// </summary>
        TCP = 0,

        /// <summary>
        /// UDP
        /// </summary>
        UDP = 1,

        /// <summary>
        ///  DNS
        /// </summary>
        DNS = 2,

        /// <summary>
        /// ICMP
        /// </summary>
        ICMP = 3,
    }

    /// <summary>
    /// State of NAT session (TCP)
    /// </summary>
    public enum VpnRpcNatTcpState
    {
        /// <summary>
        /// Connecting
        /// </summary>
        Connecting = 0,

        /// <summary>
        /// Send the RST (Connection failure or disconnected)
        /// </summary>
        SendReset = 1,

        /// <summary>
        /// Connection complete
        /// </summary>
        Connected = 2,

        /// <summary>
        /// Connection established
        /// </summary>
        Established = 3,

        /// <summary>
        /// Wait for socket disconnection
        /// </summary>
        WaitDisconnect = 4,
    }

    /// <summary>
    /// VpnRpcEnumNat List Item
    /// </summary>
    public class VpnRpcEnumNatItem
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// Protocol
        /// </summary>
        public VpnRpcNatProtocol Protocol_u32;

        /// <summary>
        /// Source IP address
        /// </summary>
        public string SrcIp_ip;

        /// <summary>
        /// Source host name
        /// </summary>
        public string SrcHost_str;

        /// <summary>
        /// Source port number
        /// </summary>
        public uint SrcPort_u32;

        /// <summary>
        /// Destination IP address
        /// </summary>
        public string DestIp_ip;

        /// <summary>
        /// Destination host name
        /// </summary>
        public string DestHost_str;

        /// <summary>
        /// Destination port number
        /// </summary>
        public uint DestPort_u32;

        /// <summary>
        /// Connection time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Last communication time
        /// </summary>
        public DateTime LastCommTime_dt;

        /// <summary>
        /// Transmission size
        /// </summary>
        public ulong SendSize_u64;

        /// <summary>
        /// Receive size
        /// </summary>
        public ulong RecvSize_u64;

        /// <summary>
        /// TCP state
        /// </summary>
        public VpnRpcNatTcpState TcpStatus_u32;
    }

    /// <summary>
    /// RPC_ENUM_NAT
    /// </summary>
    public class VpnRpcEnumNat
    {
        /// <summary>
        /// Virtual Hub Name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// NAT item
        /// </summary>
        public VpnRpcEnumNatItem[] NatTable;
    }

    /// <summary>
    /// Enumeration item of VPN session
    /// </summary>
    public class VpnRpcEnumSessionItem
    {
        /// <summary>
        /// Session name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Remote session
        /// </summary>
        public bool RemoteSession_bool;

        /// <summary>
        /// Remote server name
        /// </summary>
        public string RemoteHostname_str;

        /// <summary>
        /// User name
        /// </summary>
        public string Username_str;

        /// <summary>
        /// IP address
        /// </summary>
        public string ClientIP_ip;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// Maximum number of underlying TCP connections
        /// </summary>
        public uint MaxNumTcp_u32;

        /// <summary>
        /// Number of current underlying TCP connections
        /// </summary>
        public uint CurrentNumTcp_u32;

        /// <summary>
        /// Packet size transmitted
        /// </summary>
        public ulong PacketSize_u64;

        /// <summary>
        /// Number of packets transmitted
        /// </summary>
        public ulong PacketNum_u64;

        /// <summary>
        /// Is a Cascade VPN session
        /// </summary>
        public bool LinkMode_bool;

        /// <summary>
        /// Is a SecureNAT VPN session
        /// </summary>
        public bool SecureNATMode_bool;

        /// <summary>
        /// Is the VPN session for Local Bridge
        /// </summary>
        public bool BridgeMode_bool;

        /// <summary>
        /// Is a Layer-3 Switch VPN session
        /// </summary>
        public bool Layer3Mode_bool;

        /// <summary>
        /// Is in Bridge Mode
        /// </summary>
        public bool Client_BridgeMode_bool;

        /// <summary>
        /// Is in Monitor Mode
        /// </summary>
        public bool Client_MonitorMode_bool;

        /// <summary>
        /// VLAN ID
        /// </summary>
        public uint VLanId_u32;

        /// <summary>
        /// Unique ID of the VPN Session
        /// </summary>
        public byte[] UniqueId_bin;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Last communication date and time
        /// </summary>
        public DateTime LastCommTime_dt;
    }

    /// <summary>
    /// Enumerate VPN sessions
    /// </summary>
    public class VpnRpcEnumSession
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// VPN sessions list
        /// </summary>
        public VpnRpcEnumSessionItem[] SessionList;
    }

    /// <summary>
    /// Enumeration item of user
    /// </summary>
    public class VpnRpcEnumUserItem
    {
        /// <summary>
        /// User name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Group name
        /// </summary>
        public string GroupName_str;

        /// <summary>
        /// Real name
        /// </summary>
        public string Realname_utf;

        /// <summary>
        /// Note
        /// </summary>
        public string Note_utf;

        /// <summary>
        /// Authentication method
        /// </summary>
        public VpnRpcUserAuthType AuthType_u32;

        /// <summary>
        /// Number of logins
        /// </summary>
        public uint NumLogin_u32;

        /// <summary>
        /// Last login date and time
        /// </summary>
        public DateTime LastLoginTime_dt;

        /// <summary>
        /// Access denied
        /// </summary>
        public bool DenyAccess_bool;

        /// <summary>
        /// Flag of whether the traffic variable is set
        /// </summary>
        public bool IsTrafficFilled_bool;

        /// <summary>
        /// Flag of whether expiration date variable is set
        /// </summary>
        public bool IsExpiresFilled_bool;

        /// <summary>
        /// Expiration date
        /// </summary>
        public DateTime Expires_dt;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Ex.Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Ex.Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Ex.Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;
    }

    /// <summary>
    /// Enumeration of user
    /// </summary>
    public class VpnRpcEnumUser
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// User list
        /// </summary>
        public VpnRpcEnumUserItem[] UserList;
    }

    /// <summary>
    /// Source IP Address Limit List Item
    /// </summary>
    public class VpnAc
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// Priority
        /// </summary>
        public uint Priority_u32;

        /// <summary>
        /// Deny access
        /// </summary>
        public bool Deny_bool;

        /// <summary>
        /// Set true if you want to specify the SubnetMask_ip item.
        /// </summary>
        public bool Masked_bool;

        /// <summary>
        /// IP address
        /// </summary>
        public string IpAddress_ip;

        /// <summary>
        /// Subnet mask, valid only if Masked_bool == true
        /// </summary>
        public string SubnetMask_ip;
    }

    /// <summary>
    /// Source IP Address Limit List
    /// </summary>
    public class VpnRpcAcList
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Source IP Address Limit List
        /// </summary>
        public VpnAc[] ACList;
    }

    /// <summary>
    /// Message
    /// </summary>
    public class VpnRpcMsg
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Message (Unicode strings acceptable)
        /// </summary>
        public byte[] Msg_bin;
    }

    /// <summary>
    /// Get / Set the Azure state
    /// </summary>
    public class VpnRpcAzureStatus
    {
        /// <summary>
        /// Whether VPN Azure Function is Enabled
        /// </summary>
        public bool IsEnabled_bool;

        /// <summary>
        /// Whether connection to VPN Azure Cloud Server is established
        /// </summary>
        public bool IsConnected_bool;
    }

    /// <summary>
    /// Local Bridge support information
    /// </summary>
    public class VpnRpcBridgeSupport
    {
        /// <summary>
        /// Whether the OS supports the Local Bridge function
        /// </summary>
        public bool IsBridgeSupportedOs_bool;

        /// <summary>
        /// Whether WinPcap is necessary to install
        /// </summary>
        public bool IsWinPcapNeeded_bool;
    }

    /// <summary>
    /// Get the CA of HUB
    /// </summary>
    public class VpnRpcHubGetCA
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The key id of the certificate
        /// </summary>
        public uint Key_u32;

        /// <summary>
        /// The body of the X.509 certificate
        /// </summary>
        public byte[] Cert_bin;
    }

    /// <summary>
    /// Caps item of the VPN Server
    /// </summary>
    public class VpnCaps
    {
        /// <summary>
        /// Name
        /// </summary>
        public string CapsName_str;

        /// <summary>
        /// Value
        /// </summary>
        public uint CapsValue_u32;

        /// <summary>
        /// Descrption
        /// </summary>
        public string CapsDescrption_utf;
    }

    /// <summary>
    /// Caps list of the VPN Server
    ///</summary>
    public class VpnCapslist
    {
        /// <summary>
        /// Caps list of the VPN Server
        /// </summary>
        public VpnCaps[] CapsList;
    }

    /// <summary>
    /// Config operation
    /// </summary>
    public class VpnRpcConfig
    {
        /// <summary>
        /// File name (valid only for returning from the server)
        /// </summary>
        public string FileName_str;

        /// <summary>
        /// File data
        /// </summary>
        public byte[] FileData_bin;
    }

    /// <summary>
    /// Connection information
    /// </summary>
    public class VpnRpcConnectionInfo
    {
        /// <summary>
        /// Connection name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Type
        /// </summary>
        public VpnRpcConnectionType Type_u32;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Port number
        /// </summary>
        public uint Port_u32;

        /// <summary>
        /// Connected time
        /// </summary>
        public DateTime ConnectedTime_dt;

        /// <summary>
        /// Server string
        /// </summary>
        public string ServerStr_str;

        /// <summary>
        /// Server version
        /// </summary>
        public uint ServerVer_u32;

        /// <summary>
        /// Server build number
        /// </summary>
        public uint ServerBuild_u32;

        /// <summary>
        /// Client string
        /// </summary>
        public string ClientStr_str;

        /// <summary>
        /// Client version
        /// </summary>
        public uint ClientVer_u32;

        /// <summary>
        /// Client build number
        /// </summary>
        public uint ClientBuild_u32;
    }

    /// <summary>
    /// Proxy type
    /// </summary>
    public enum VpnRpcProxyType
    {
        /// <summary>
        /// Direct TCP connection
        /// </summary>
        Direct = 0,

        /// <summary>
        /// Connection via HTTP proxy server
        /// </summary>
        HTTP = 1,

        /// <summary>
        /// Connection via SOCKS proxy server
        /// </summary>
        SOCKS = 2,
    }

    /// <summary>
    /// The current status of the DDNS
    /// </summary>
    public class VpnDDnsClientStatus
    {
        /// <summary>
        /// Last error code (IPv4)
        /// </summary>
        public uint Err_IPv4_u32;

        /// <summary>
        /// Last error string (IPv4)
        /// </summary>
        public string ErrStr_IPv4_utf;

        /// <summary>
        /// Last error code (IPv6)
        /// </summary>
        public uint Err_IPv6_u32;

        /// <summary>
        /// Last error string (IPv6)
        /// </summary>
        public string ErrStr_IPv6_utf;

        /// <summary>
        /// Current DDNS host name
        /// </summary>
        public string CurrentHostName_str;

        /// <summary>
        /// Current FQDN of the DDNS hostname
        /// </summary>
        public string CurrentFqdn_str;

        /// <summary>
        /// DDNS suffix
        /// </summary>
        public string DnsSuffix_str;

        /// <summary>
        /// Current IPv4 address of the VPN Server
        /// </summary>
        public string CurrentIPv4_str;

        /// <summary>
        /// Current IPv6 address of the VPN Server
        /// </summary>
        public string CurrentIPv6_str;
    }

    /// <summary>
    /// Internet connection settings
    /// </summary>
    public class VpnInternetSetting
    {
        /// <summary>
        /// Type of proxy server
        /// </summary>
        public VpnRpcProxyType ProxyType_u32;

        /// <summary>
        /// Proxy server host name
        /// </summary>
        public string ProxyHostName_str;

        /// <summary>
        /// Proxy server port number
        /// </summary>
        public uint ProxyPort_u32;

        /// <summary>
        /// Proxy server user name
        /// </summary>
        public string ProxyUsername_str;

        /// <summary>
        /// Proxy server password
        /// </summary>
        public string ProxyPassword_str;
    }

    /// <summary>
    /// Administration options
    /// </summary>
    public class VpnAdminOption
    {
        /// <summary>
        /// Name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// Data
        /// </summary>
        public uint Value_u32;

        /// <summary>
        /// Descrption
        /// </summary>
        public string Descrption_utf;
    }

    /// <summary>
    /// Administration options list
    /// </summary>
    public class VpnRpcAdminOption
    {
        /// <summary>
        /// Virtual HUB name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// List data
        /// </summary>
        public VpnAdminOption[] AdminOptionList;
    }

    /// <summary>
    /// Connection state to the controller
    /// </summary>
    public class VpnRpcFarmConnectionStatus
    {
        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Port number
        /// </summary>
        public uint Port_u32;

        /// <summary>
        /// Online state
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// Last error code
        /// </summary>
        public uint LastError_u32;

        /// <summary>
        /// Connection start time
        /// </summary>
        public DateTime StartedTime_dt;

        /// <summary>
        /// First connection time
        /// </summary>
        public DateTime FirstConnectedTime_dt;

        /// <summary>
        /// Connection time of this time
        /// </summary>
        public DateTime CurrentConnectedTime_dt;

        /// <summary>
        /// Number of retries
        /// </summary>
        public uint NumTry_u32;

        /// <summary>
        /// Number of connection count
        /// </summary>
        public uint NumConnected_u32;

        /// <summary>
        /// Connection failure count
        /// </summary>
        public uint NumFailed_u32;
    }

    /// <summary>
    /// HUB item of each farm member
    /// </summary>
    public class VpnRpcFarmHub
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Dynamic HUB
        /// </summary>
        public bool DynamicHub_bool;
    }


    /// <summary>
    /// Server farm member information acquisition
    /// </summary>
    public class VpnRpcFarmInfo
    {
        /// <summary>
        /// ID
        /// </summary>
        public uint Id_u32;

        /// <summary>
        /// The flag if the server is Cluster Controller (false: Cluster Member servers)
        /// </summary>
        public bool Controller_bool;

        /// <summary>
        /// Connection Established Time
        /// </summary>
        public DateTime ConnectedTime_dt;

        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Host name
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// Point
        /// </summary>
        public uint Point_u32;

        /// <summary>
        /// Number of Public Ports
        /// </summary>
        public uint NumPort_u32;

        /// <summary>
        /// Public Ports
        /// </summary>
        public uint[] Ports_u32;

        /// <summary>
        /// Server certificate
        /// </summary>
        public byte[] ServerCert_bin;

        /// <summary>
        /// Number of farm HUB
        /// </summary>
        public uint NumFarmHub_u32;

        /// <summary>
        /// The hosted Virtual Hub list
        /// </summary>
        public VpnRpcFarmHub[] HubsList;

        /// <summary>
        /// Number of hosted VPN sessions
        /// </summary>
        public uint NumSessions_u32;

        /// <summary>
        /// Number of TCP connections
        /// </summary>
        public uint NumTcpConnections_u32;

        /// <summary>
        /// Performance Standard Ratio
        /// </summary>
        public uint Weight_u32;
    }

    /// <summary>
    /// Server farm configuration
    /// </summary>
    public class VpnRpcFarm
    {
        /// <summary>
        /// Type of server
        /// </summary>
        public VpnRpcServerType ServerType_u32;

        /// <summary>
        /// Valid only for Cluster Member servers. Number of the Ports_u32 element.
        /// </summary>
        public uint NumPort_u32;

        /// <summary>
        /// Valid only for Cluster Member servers. Specify the list of public port numbers on this server. The list must have at least one public port number set, and it is also possible to set multiple public port numbers.
        /// </summary>
        public uint[] Ports_u32;

        /// <summary>
        /// Valid only for Cluster Member servers. Specify the public IP address of this server. If you wish to leave public IP address unspecified, specify the empty string. When a public IP address is not specified, the IP address of the network interface used when connecting to the cluster controller will be automatically used.
        /// </summary>
        public string PublicIp_ip;

        /// <summary>
        /// Valid only for Cluster Member servers. Specify the host name or IP address of the destination cluster controller.
        /// </summary>
        public string ControllerName_str;

        /// <summary>
        /// Valid only for Cluster Member servers. Specify the TCP port number of the destination cluster controller.
        /// </summary>
        public uint ControllerPort_u32;

        /// <summary>
        /// Valid only for Cluster Member servers. Specify the password required to connect to the destination controller. It needs to be the same as an administrator password on the destination controller.
        /// </summary>
        public string MemberPasswordPlaintext_str;

        /// <summary>
        /// This sets a value for the performance standard ratio of this VPN Server. This is the standard value for when load balancing is performed in the cluster. For example, making only one machine 200 while the other members have a status of 100, will regulate that machine to receive twice as many connections as the other members. Specify 1 or higher for the value. If this parameter is left unspecified, 100 will be used.
        /// </summary>
        public uint Weight_u32;

        /// <summary>
        /// Valid only for Cluster Controller server. By specifying true, the VPN Server will operate only as a controller on the cluster and it will always distribute general VPN Client connections to members other than itself. This function is used in high-load environments.
        /// </summary>
        public bool ControllerOnly_bool;
    }

    /// <summary>
    /// Log switch type
    /// </summary>
    public enum VpnRpcLogSwitchType
    {
        /// <summary>
        /// No switching
        /// </summary>
        No = 0,

        /// <summary>
        /// Secondly basis
        /// </summary>
        Second = 1,

        /// <summary>
        /// Minutely basis
        /// </summary>
        Minute = 2,

        /// <summary>
        /// Hourly basis
        /// </summary>
        Hour = 3,

        /// <summary>
        /// Daily basis
        /// </summary>
        Day = 4,

        /// <summary>
        /// Monthly basis
        /// </summary>
        Month = 5,
    }

    /// <summary>
    /// Packet log settings
    /// </summary>
    public enum VpnRpcPacketLogSetting
    {
        /// <summary>
        /// Not save
        /// </summary>
        None = 0,

        /// <summary>
        /// Only header
        /// </summary>
        Header = 1,

        /// <summary>
        /// All payloads
        /// </summary>
        All = 2,
    }

    /// <summary>
    /// Packet log settings array index
    /// </summary>
    public enum VpnRpcPacketLogSettingIndex
    {
        /// <summary>
        /// TCP connection log
        /// </summary>
        TcpConnection = 0,

        /// <summary>
        /// TCP packet log
        /// </summary>
        TcpAll = 1,

        /// <summary>
        /// DHCP Log
        /// </summary>
        Dhcp = 2,

        /// <summary>
        /// UDP log
        /// </summary>
        Udp = 3,

        /// <summary>
        /// ICMP log
        /// </summary>
        Icmp = 4,

        /// <summary>
        /// IP log
        /// </summary>
        Ip = 5,

        /// <summary>
        ///  ARP log
        /// </summary>
        Arp = 6,

        /// <summary>
        /// Ethernet log
        /// </summary>
        Ethernet = 7,
    }

    /// <summary>
    /// HUB log settings
    /// </summary>
    public class VpnRpcHubLog
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The flag to enable / disable saving the security log
        /// </summary>
        public bool SaveSecurityLog_bool;

        /// <summary>
        /// The log filename switching setting of the security log
        /// </summary>
        public VpnRpcLogSwitchType SecurityLogSwitchType_u32;

        /// <summary>
        /// The flag to enable / disable saving the security log
        /// </summary>
        public bool SavePacketLog_bool;

        /// <summary>
        /// The log filename switching settings of the packet logs
        /// </summary>
        public VpnRpcLogSwitchType PacketLogSwitchType_u32;

        /// <summary>
        /// Specify the save contents of the packet logs (uint * 16 array). The index numbers: TcpConnection = 0, TcpAll = 1, DHCP = 2, UDP = 3, ICMP = 4, IP = 5, ARP = 6, Ethernet = 7.
        /// </summary>
        public VpnRpcPacketLogSetting[] PacketLogConfig_u32 = new VpnRpcPacketLogSetting[16];
    }

    /// <summary>
    /// RADIUS server options
    /// </summary>
    public class VpnRpcRadius
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// RADIUS server name
        /// </summary>
        public string RadiusServerName_str;

        /// <summary>
        /// RADIUS port number
        /// </summary>
        public uint RadiusPort_u32;

        /// <summary>
        /// Secret key
        /// </summary>
        public string RadiusSecret_str;

        /// <summary>
        /// Radius retry interval
        /// </summary>
        public uint RadiusRetryInterval_u32;
    }

    /// <summary>
    /// Get the state HUB
    /// </summary>
    public class VpnRpcHubStatus
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Online
        /// </summary>
        public bool Online_bool;

        /// <summary>
        /// Type of HUB
        /// </summary>
        public VpnRpcHubType HubType_u32;

        /// <summary>
        /// Number of sessions
        /// </summary>
        public uint NumSessions_u32;

        /// <summary>
        /// Number of sessions (client mode)
        /// </summary>
        public uint NumSessionsClient_u32;

        /// <summary>
        /// Number of sessions (bridge mode)
        /// </summary>
        public uint NumSessionsBridge_u32;

        /// <summary>
        /// Number of Access list entries
        /// </summary>
        public uint NumAccessLists_u32;

        /// <summary>
        /// Number of users
        /// </summary>
        public uint NumUsers_u32;

        /// <summary>
        /// Number of groups
        /// </summary>
        public uint NumGroups_u32;

        /// <summary>
        /// Number of MAC table entries
        /// </summary>
        public uint NumMacTables_u32;

        /// <summary>
        /// Number of IP table entries
        /// </summary>
        public uint NumIpTables_u32;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;

        /// <summary>
        /// Whether SecureNAT is enabled
        /// </summary>
        public bool SecureNATEnabled_bool;

        /// <summary>
        /// Last communication date and time
        /// </summary>
        public DateTime LastCommTime_dt;

        /// <summary>
        /// Last login date and time
        /// </summary>
        public DateTime LastLoginTime_dt;

        /// <summary>
        /// Creation date and time
        /// </summary>
        public DateTime CreatedTime_dt;

        /// <summary>
        /// Number of logins
        /// </summary>
        public uint NumLogin_u32;
    }

    /// <summary>
    /// List of services provided by IPsec server
    /// </summary>
    public class VpnIPsecServices
    {
        /// <summary>
        /// Enable or Disable the L2TP Server Function (Raw L2TP with No Encryptions). To accept special VPN clients, enable this option.
        /// </summary>
        public bool L2TP_Raw_bool;

        /// <summary>
        /// Enable or Disable the L2TP over IPsec Server Function. To accept VPN connections from iPhone, iPad, Android, Windows or Mac OS X, enable this option.
        /// </summary>
        public bool L2TP_IPsec_bool;

        /// <summary>
        /// Enable or Disable the EtherIP / L2TPv3 over IPsec Server Function (for site-to-site VPN Server function). Router Products which are compatible with EtherIP over IPsec can connect to Virtual Hubs on the VPN Server and establish Layer-2 (Ethernet) Bridging.
        /// </summary>
        public bool EtherIP_IPsec_bool;

        /// <summary>
        /// Specify the IPsec Pre-Shared Key. An IPsec Pre-Shared Key is also called as "PSK" or "secret". Specify it equal or less than 8 letters, and distribute it to every users who will connect to the VPN Server. Please note: Google Android 4.0 has a bug which a Pre-Shared Key with 10 or more letters causes a unexpected behavior. For that reason, the letters of a Pre-Shared Key should be 9 or less characters.
        /// </summary>
        public string IPsec_Secret_str;

        /// <summary>
        /// Specify the default Virtual HUB in a case of omitting the name of HUB on the Username. Users should specify their username such as "Username@Target Virtual HUB Name" to connect this L2TP Server. If the designation of the Virtual Hub is omitted, the above HUB will be used as the target.
        /// </summary>
        public string L2TP_DefaultHub_str;
    }

    /// <summary>
    /// Keep alive protocol
    /// </summary>
    public enum VpnRpcKeepAliveProtocol
    {
        /// <summary>
        /// TCP
        /// </summary>
        TCP = 0,

        /// <summary>
        /// UDP
        /// </summary>
        UDP = 1,
    }

    /// <summary>
    /// Keep Alive settings
    /// </summary>
    public class VpnRpcKeep
    {
        /// <summary>
        /// The flag to enable keep-alive to the Internet
        /// </summary>
        public bool UseKeepConnect_bool;

        /// <summary>
        /// Specify the host name or IP address of the destination
        /// </summary>
        public string KeepConnectHost_str;

        /// <summary>
        /// Specify the port number of the destination
        /// </summary>
        public uint KeepConnectPort_u32;

        /// <summary>
        /// Protocol type
        /// </summary>
        public VpnRpcKeepAliveProtocol KeepConnectProtocol_u32;

        /// <summary>
        /// Interval Between Packets Sends (Seconds)
        /// </summary>
        public uint KeepConnectInterval_u32;
    }

    /// <summary>
    /// State of the client session
    /// </summary>
    public enum VpnRpcClientSessionStatus
    {
        /// <summary>
        /// Connecting
        /// </summary>
        Connecting = 0,

        /// <summary>
        /// Negotiating
        /// </summary>
        Negotiation = 1,

        /// <summary>
        /// During user authentication
        /// </summary>
        Auth = 2,

        /// <summary>
        /// Connection complete
        /// </summary>
        Established = 3,

        /// <summary>
        /// Wait to retry
        /// </summary>
        Retry = 4,

        /// <summary>
        /// Idle state
        /// </summary>
        Idle = 5,
    }

    /// <summary>
    /// Get the link state
    /// </summary>
    public class VpnRpcLinkStatus
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_Ex_str;

        /// <summary>
        /// The name of the cascade connection
        /// </summary>
        public string AccountName_utf;

        /// <summary>
        /// The flag whether the cascade connection is enabled
        /// </summary>
        public bool Active_bool;

        /// <summary>
        /// The flag whether the cascade connection is established
        /// </summary>
        public bool Connected_bool;

        /// <summary>
        /// The session status
        /// </summary>
        public VpnRpcClientSessionStatus SessionStatus_u32;

        /// <summary>
        /// The destination VPN server name
        /// </summary>
        public string ServerName_str;

        /// <summary>
        /// The port number of the server
        /// </summary>
        public uint ServerPort_u32;

        /// <summary>
        /// Server product name
        /// </summary>
        public string ServerProductName_str;

        /// <summary>
        /// Server product version
        /// </summary>
        public uint ServerProductVer_u32;

        /// <summary>
        /// Server product build number
        /// </summary>
        public uint ServerProductBuild_u32;

        /// <summary>
        /// Server's X.509 certificate
        /// </summary>
        public byte[] ServerX_bin;

        /// <summary>
        /// Client certificate
        /// </summary>
        public byte[] ClientX_bin;

        /// <summary>
        /// Connection start time
        /// </summary>
        public DateTime StartTime_dt;

        /// <summary>
        /// Connection completion time of the first connection
        /// </summary>
        public DateTime FirstConnectionEstablisiedTime_dt;

        /// <summary>
        /// Connection completion time of this connection
        /// </summary>
        public DateTime CurrentConnectionEstablishTime_dt;

        /// <summary>
        /// Number of connections have been established so far
        /// </summary>
        public uint NumConnectionsEatablished_u32;

        /// <summary>
        /// Half-connection
        /// </summary>
        public bool HalfConnection_bool;

        /// <summary>
        /// VoIP / QoS
        /// </summary>
        public bool QoS_bool;

        /// <summary>
        /// Maximum number of the underlying TCP connections
        /// </summary>
        public uint MaxTcpConnections_u32;

        /// <summary>
        /// Number of current underlying TCP connections
        /// </summary>
        public uint NumTcpConnections_u32;

        /// <summary>
        /// Number of underlying inbound TCP connections
        /// </summary>
        public uint NumTcpConnectionsUpload_u32;

        /// <summary>
        /// Number of underlying outbound TCP connections
        /// </summary>
        public uint NumTcpConnectionsDownload_u32;

        /// <summary>
        /// Use of encryption
        /// </summary>
        public bool UseEncrypt_bool;

        /// <summary>
        /// Cipher algorithm name
        /// </summary>
        public string CipherName_str;

        /// <summary>
        /// Use of compression
        /// </summary>
        public bool UseCompress_bool;

        /// <summary>
        /// The flag whether this is a R-UDP session
        /// </summary>
        public bool IsRUDPSession_bool;

        /// <summary>
        /// Underlying physical communication protocol
        /// </summary>
        public string UnderlayProtocol_str;

        /// <summary>
        /// The UDP acceleration is enabled
        /// </summary>
        public bool IsUdpAccelerationEnabled_bool;

        /// <summary>
        /// The UDP acceleration is being actually used
        /// </summary>
        public bool IsUsingUdpAcceleration_bool;

        /// <summary>
        /// Session name
        /// </summary>
        public string SessionName_str;

        /// <summary>
        /// Connection name
        /// </summary>
        public string ConnectionName_str;

        /// <summary>
        /// Session key
        /// </summary>
        public byte[] SessionKey_bin;

        /// <summary>
        /// Total transmitted data size
        /// </summary>
        public ulong TotalSendSize_u64;

        /// <summary>
        /// Total received data size
        /// </summary>
        public ulong TotalRecvSize_u64;

        /// <summary>
        /// Total transmitted data size (no compression)
        /// </summary>
        public ulong TotalSendSizeReal_u64;

        /// <summary>
        /// Total received data size (no compression)
        /// </summary>
        public ulong TotalRecvSizeReal_u64;

        /// <summary>
        /// The flag whether the VPN session is Bridge Mode
        /// </summary>
        public bool IsBridgeMode_bool;

        /// <summary>
        /// The flag whether the VPN session is Monitor mode
        /// </summary>
        public bool IsMonitorMode_bool;

        /// <summary>
        /// VLAN ID
        /// </summary>
        public uint VLanId_u32;
    }

    /// <summary>
    /// Setting of SSTP and OpenVPN
    /// </summary>
    public class VpnOpenVpnSstpConfig
    {
        /// <summary>
        /// Specify true to enable the OpenVPN Clone Server Function. Specify false to disable.
        /// </summary>
        public bool EnableOpenVPN_bool;

        /// <summary>
        /// Specify UDP ports to listen for OpenVPN. Multiple UDP ports can be specified with splitting by space or comma letters, for example: "1194, 2001, 2010, 2012". The default port for OpenVPN is UDP 1194. You can specify any other UDP ports.
        /// </summary>
        public string OpenVPNPortList_str;

        /// <summary>
        /// pecify true to enable the Microsoft SSTP VPN Clone Server Function. Specify false to disable.
        /// </summary>
        public bool EnableSSTP_bool;
    }

    /// <summary>
    /// Virtual host option
    /// </summary>
    public class VpnVhOption
    {
        /// <summary>
        /// Target Virtual HUB name
        /// </summary>
        public string RpcHubName_str;

        /// <summary>
        /// MAC address
        /// </summary>
        public byte[] MacAddress_bin;

        /// <summary>
        /// IP address
        /// </summary>
        public string Ip_ip;

        /// <summary>
        /// Subnet mask
        /// </summary>
        public string Mask_ip;

        /// <summary>
        /// Use flag of the Virtual NAT function
        /// </summary>
        public bool UseNat_bool;

        /// <summary>
        /// MTU value (Standard: 1500)
        /// </summary>
        public uint Mtu_u32;

        /// <summary>
        /// NAT TCP timeout in seconds
        /// </summary>
        public uint NatTcpTimeout_u32;

        /// <summary>
        /// NAT UDP timeout in seconds
        /// </summary>
        public uint NatUdpTimeout_u32;

        /// <summary>
        /// Using flag of DHCP function
        /// </summary>
        public bool UseDhcp_bool;

        /// <summary>
        /// Specify the start point of the address band to be distributed to the client. (Example: 192.168.30.10)
        /// </summary>
        public string DhcpLeaseIPStart_ip;

        /// <summary>
        /// Specify the end point of the address band to be distributed to the client. (Example: 192.168.30.200)
        /// </summary>
        public string DhcpLeaseIPEnd_ip;

        /// <summary>
        /// Specify the subnet mask to be specified for the client. (Example: 255.255.255.0)
        /// </summary>
        public string DhcpSubnetMask_ip;

        /// <summary>
        /// Specify the expiration date in second units for leasing an IP address to a client.
        /// </summary>
        public uint DhcpExpireTimeSpan_u32;

        /// <summary>
        /// Specify the IP address of the default gateway to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify 0 or none, then the client will not be notified of the default gateway.
        /// </summary>
        public string DhcpGatewayAddress_ip;

        /// <summary>
        /// Specify the IP address of the primary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
        /// </summary>
        public string DhcpDnsServerAddress_ip;

        /// <summary>
        /// Specify the IP address of the secondary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
        /// </summary>
        public string DhcpDnsServerAddress2_ip;

        /// <summary>
        /// Specify the domain name to be notified to the client. If you specify none, then the client will not be notified of the domain name.
        /// </summary>
        public string DhcpDomainName_str;

        /// <summary>
        /// Specify whether or not to save the Virtual DHCP Server operation in the Virtual Hub security log. Specify true to save it. This value is interlinked with the Virtual NAT Function log save setting.
        /// </summary>
        public bool SaveLog_bool;

        /// <summary>
        /// The flag to enable the DhcpPushRoutes_str field.
        /// </summary>
        public bool ApplyDhcpPushRoutes_bool;

        /// <summary>
        /// Specify the static routing table to push. Example: "192.168.5.0/255.255.255.0/192.168.4.254, 10.0.0.0/255.0.0.0/192.168.4.253" Split multiple entries (maximum: 64 entries) by comma or space characters. Each entry must be specified in the "IP network address/subnet mask/gateway IP address" format. This Virtual DHCP Server can push the classless static routes (RFC 3442) with DHCP reply messages to VPN clients. Whether or not a VPN client can recognize the classless static routes (RFC 3442) depends on the target VPN client software. SoftEther VPN Client and OpenVPN Client are supporting the classless static routes. On L2TP/IPsec and MS-SSTP protocols, the compatibility depends on the implementation of the client software. You can realize the split tunneling if you clear the default gateway field on the Virtual DHCP Server options. On the client side, L2TP/IPsec and MS-SSTP clients need to be configured not to set up the default gateway for the split tunneling usage. You can also push the classless static routes (RFC 3442) by your existing external DHCP server. In that case, disable the Virtual DHCP Server function on SecureNAT, and you need not to set up the classless routes on this API. See the RFC 3442 to understand the classless routes.
        /// </summary>
        public string DhcpPushRoutes_str;
    }

    /// <summary>
    /// RPC_NAT_STATUS
    /// </summary>
    public class VpnRpcNatStatus
    {
        /// <summary>
        /// Virtual Hub Name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Number of TCP sessions
        /// </summary>
        public uint NumTcpSessions_u32;

        /// <summary>
        /// Ntmber of UDP sessions
        /// </summary>
        public uint NumUdpSessions_u32;

        /// <summary>
        /// Nymber of ICMP sessions
        /// </summary>
        public uint NumIcmpSessions_u32;

        /// <summary>
        /// Number of DNS sessions
        /// </summary>
        public uint NumDnsSessions_u32;

        /// <summary>
        /// Number of DHCP clients
        /// </summary>
        public uint NumDhcpClients_u32;

        /// <summary>
        /// Whether the NAT is operating in the Kernel Mode
        /// </summary>
        public bool IsKernelMode_bool;

        /// <summary>
        /// Whether the NAT is operating in the Raw IP Mode
        /// </summary>
        public bool IsRawIpMode_bool;
    }

    /// <summary>
    /// Key pair
    /// </summary>
    public class VpnRpcKeyPair
    {
        /// <summary>
        /// The body of the certificate
        /// </summary>
        public byte[] Cert_bin;

        /// <summary>
        /// The body of the private key
        /// </summary>
        public byte[] Key_bin;
    }

    /// <summary>
    /// Single string value
    /// </summary>
    public class VpnRpcStr
    {
        /// <summary>
        /// A string value
        /// </summary>
        public string String_str;
    }

    /// <summary>
    /// Type of VPN Server
    /// </summary>
    public enum VpnRpcServerType
    {
        /// <summary>
        /// Stand-alone server
        /// </summary>
        Standalone = 0,

        /// <summary>
        /// Farm controller server
        /// </summary>
        FarmController = 1,

        /// <summary>
        /// Farm member server
        /// </summary>
        FarmMember = 2,
    }

    /// <summary>
    /// Operating system type
    /// </summary>
    public enum VpnRpcOsType
    {
        /// <summary>
        /// Windows 95
        /// </summary>
        WINDOWS_95 = 1100,

        /// <summary>
        /// Windows 98
        /// </summary>
        WINDOWS_98 = 1200,

        /// <summary>
        /// Windows Me
        /// </summary>
        WINDOWS_ME = 1300,

        /// <summary>
        /// Windows (unknown)
        /// </summary>
        WINDOWS_UNKNOWN = 1400,

        /// <summary>
        /// Windows NT 4.0 Workstation
        /// </summary>
        WINDOWS_NT_4_WORKSTATION = 2100,

        /// <summary>
        /// Windows NT 4.0 Server
        /// </summary>
        WINDOWS_NT_4_SERVER = 2110,

        /// <summary>
        /// Windows NT 4.0 Server, Enterprise Edition
        /// </summary>
        WINDOWS_NT_4_SERVER_ENTERPRISE = 2111,

        /// <summary>
        /// Windows NT 4.0 Terminal Server
        /// </summary>
        WINDOWS_NT_4_TERMINAL_SERVER = 2112,

        /// <summary>
        /// BackOffice Server 4.5
        /// </summary>
        WINDOWS_NT_4_BACKOFFICE = 2113,

        /// <summary>
        /// Small Business Server 4.5
        /// </summary>
        WINDOWS_NT_4_SMS = 2114,

        /// <summary>
        /// Windows 2000 Professional
        /// </summary>
        WINDOWS_2000_PROFESSIONAL = 2200,

        /// <summary>
        /// Windows 2000 Server
        /// </summary>
        WINDOWS_2000_SERVER = 2211,

        /// <summary>
        /// Windows 2000 Advanced Server
        /// </summary>
        WINDOWS_2000_ADVANCED_SERVER = 2212,

        /// <summary>
        /// Windows 2000 Datacenter Server
        /// </summary>
        WINDOWS_2000_DATACENTER_SERVER = 2213,

        /// <summary>
        /// BackOffice Server 2000
        /// </summary>
        WINDOWS_2000_BACKOFFICE = 2214,

        /// <summary>
        /// Small Business Server 2000
        /// </summary>
        WINDOWS_2000_SBS = 2215,

        /// <summary>
        /// Windows XP Home Edition
        /// </summary>
        WINDOWS_XP_HOME = 2300,

        /// <summary>
        /// Windows XP Professional
        /// </summary>
        WINDOWS_XP_PROFESSIONAL = 2301,

        /// <summary>
        /// Windows Server 2003 Web Edition
        /// </summary>
        WINDOWS_2003_WEB = 2410,

        /// <summary>
        /// Windows Server 2003 Standard Edition
        /// </summary>
        WINDOWS_2003_STANDARD = 2411,

        /// <summary>
        /// Windows Server 2003 Enterprise Edition
        /// </summary>
        WINDOWS_2003_ENTERPRISE = 2412,

        /// <summary>
        /// Windows Server 2003 DataCenter Edition
        /// </summary>
        WINDOWS_2003_DATACENTER = 2413,

        /// <summary>
        /// BackOffice Server 2003
        /// </summary>
        WINDOWS_2003_BACKOFFICE = 2414,

        /// <summary>
        /// Small Business Server 2003
        /// </summary>
        WINDOWS_2003_SBS = 2415,

        /// <summary>
        /// Windows Vista
        /// </summary>
        WINDOWS_LONGHORN_PROFESSIONAL = 2500,

        /// <summary>
        /// Windows Server 2008
        /// </summary>
        WINDOWS_LONGHORN_SERVER = 2510,

        /// <summary>
        /// Windows 7
        /// </summary>
        WINDOWS_7 = 2600,

        /// <summary>
        /// Windows Server 2008 R2
        /// </summary>
        WINDOWS_SERVER_2008_R2 = 2610,

        /// <summary>
        /// Windows 8
        /// </summary>
        WINDOWS_8 = 2700,

        /// <summary>
        /// Windows Server 2012
        /// </summary>
        WINDOWS_SERVER_8 = 2710,

        /// <summary>
        /// Windows 8.1
        /// </summary>
        WINDOWS_81 = 2701,

        /// <summary>
        /// Windows Server 2012 R2
        /// </summary>
        WINDOWS_SERVER_81 = 2711,

        /// <summary>
        /// Windows 10
        /// </summary>
        WINDOWS_10 = 2702,

        /// <summary>
        /// Windows Server 10
        /// </summary>
        WINDOWS_SERVER_10 = 2712,

        /// <summary>
        /// Windows 11 or later
        /// </summary>
        WINDOWS_11 = 2800,

        /// <summary>
        /// Windows Server 11 or later
        /// </summary>
        WINDOWS_SERVER_11 = 2810,

        /// <summary>
        /// Unknown UNIX
        /// </summary>
        UNIX_UNKNOWN = 3000,

        /// <summary>
        /// Linux
        /// </summary>
        LINUX = 3100,

        /// <summary>
        /// Solaris
        /// </summary>
        SOLARIS = 3200,

        /// <summary>
        /// Cygwin
        /// </summary>
        CYGWIN = 3300,

        /// <summary>
        /// BSD
        /// </summary>
        BSD = 3400,

        /// <summary>
        /// MacOS X
        /// </summary>
        MACOS_X = 3500,
    }

    /// <summary>
    /// VPN Server Information
    /// </summary>
    public class VpnRpcServerInfo
    {
        /// <summary>
        /// Server product name
        /// </summary>
        public string ServerProductName_str;

        /// <summary>
        /// Server version string
        /// </summary>
        public string ServerVersionString_str;

        /// <summary>
        /// Server build information string
        /// </summary>
        public string ServerBuildInfoString_str;

        /// <summary>
        /// Server version integer value
        /// </summary>
        public uint ServerVerInt_u32;

        /// <summary>
        /// Server build number integer value
        /// </summary>
        public uint ServerBuildInt_u32;

        /// <summary>
        /// Server host name
        /// </summary>
        public string ServerHostName_str;

        /// <summary>
        /// Type of server
        /// </summary>
        public VpnRpcServerType ServerType_u32;

        /// <summary>
        /// Build date and time of the server
        /// </summary>
        public DateTime ServerBuildDate_dt;

        /// <summary>
        /// Family name
        /// </summary>
        public string ServerFamilyName_str;

        /// <summary>
        /// OS type
        /// </summary>
        public VpnRpcOsType OsType_u32;

        /// <summary>
        /// Service pack number
        /// </summary>
        public uint OsServicePack_u32;

        /// <summary>
        /// OS system name
        /// </summary>
        public string OsSystemName_str;

        /// <summary>
        /// OS product name
        /// </summary>
        public string OsProductName_str;

        /// <summary>
        /// OS vendor name
        /// </summary>
        public string OsVendorName_str;

        /// <summary>
        /// OS version
        /// </summary>
        public string OsVersion_str;

        /// <summary>
        /// Kernel name
        /// </summary>
        public string KernelName_str;

        /// <summary>
        /// Kernel version
        /// </summary>
        public string KernelVersion_str;
    }

    /// <summary>
    /// Server status
    /// </summary>
    public class VpnRpcServerStatus
    {
        /// <summary>
        /// Type of server
        /// </summary>
        public VpnRpcServerType ServerType_u32;

        /// <summary>
        /// Total number of TCP connections
        /// </summary>
        public uint NumTcpConnections_u32;

        /// <summary>
        /// Number of Local TCP connections
        /// </summary>
        public uint NumTcpConnectionsLocal_u32;

        /// <summary>
        /// Number of remote TCP connections
        /// </summary>
        public uint NumTcpConnectionsRemote_u32;

        /// <summary>
        /// Total number of HUBs
        /// </summary>
        public uint NumHubTotal_u32;

        /// <summary>
        /// Nymber of stand-alone HUB
        /// </summary>
        public uint NumHubStandalone_u32;

        /// <summary>
        /// Number of static HUBs
        /// </summary>
        public uint NumHubStatic_u32;

        /// <summary>
        /// Number of Dynamic HUBs
        /// </summary>
        public uint NumHubDynamic_u32;

        /// <summary>
        /// Total number of sessions
        /// </summary>
        public uint NumSessionsTotal_u32;

        /// <summary>
        /// Number of local VPN sessions
        /// </summary>
        public uint NumSessionsLocal_u32;

        /// <summary>
        /// The number of remote sessions
        /// </summary>
        public uint NumSessionsRemote_u32;

        /// <summary>
        /// Number of MAC table entries (total sum of all Virtual Hubs)
        /// </summary>
        public uint NumMacTables_u32;

        /// <summary>
        /// Number of IP table entries (total sum of all Virtual Hubs)
        /// </summary>
        public uint NumIpTables_u32;

        /// <summary>
        /// Number of users (total sum of all Virtual Hubs)
        /// </summary>
        public uint NumUsers_u32;

        /// <summary>
        /// Number of groups (total sum of all Virtual Hubs)
        /// </summary>
        public uint NumGroups_u32;

        /// <summary>
        /// Number of assigned bridge licenses (Useful to make a commercial version)
        /// </summary>
        public uint AssignedBridgeLicenses_u32;

        /// <summary>
        /// Number of assigned client licenses (Useful to make a commercial version)
        /// </summary>
        public uint AssignedClientLicenses_u32;

        /// <summary>
        /// Number of Assigned bridge license (cluster-wide), useful to make a commercial version
        /// </summary>
        public uint AssignedBridgeLicensesTotal_u32;

        /// <summary>
        /// Number of assigned client licenses (cluster-wide), useful to make a commercial version
        /// </summary>
        public uint AssignedClientLicensesTotal_u32;

        /// <summary>
        /// Number of broadcast packets (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastBytes_u64")]
        public ulong Recv_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.BroadcastCount_u64")]
        public ulong Recv_BroadcastCount_u64;

        /// <summary>
        /// Unicast count (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastBytes_u64")]
        public ulong Recv_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Recv)
        /// </summary>
        [JsonProperty("Recv.UnicastCount_u64")]
        public ulong Recv_UnicastCount_u64;

        /// <summary>
        /// Number of broadcast packets (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastBytes_u64")]
        public ulong Send_BroadcastBytes_u64;

        /// <summary>
        /// Broadcast bytes (Send)
        /// </summary>
        [JsonProperty("Send.BroadcastCount_u64")]
        public ulong Send_BroadcastCount_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastBytes_u64")]
        public ulong Send_UnicastBytes_u64;

        /// <summary>
        /// Unicast bytes (Send)
        /// </summary>
        [JsonProperty("Send.UnicastCount_u64")]
        public ulong Send_UnicastCount_u64;

        /// <summary>
        /// Current time
        /// </summary>
        public DateTime CurrentTime_dt;

        /// <summary>
        /// 64 bit High-Precision Logical System Clock
        /// </summary>
        public ulong CurrentTick_u64;

        /// <summary>
        /// VPN Server Start-up time
        /// </summary>
        public DateTime StartTime_dt;

        /// <summary>
        /// Memory information: Total Memory
        /// </summary>
        public ulong TotalMemory_u64;

        /// <summary>
        /// Memory information: Used Memory
        /// </summary>
        public ulong UsedMemory_u64;

        /// <summary>
        /// Memory information: Free Memory
        /// </summary>
        public ulong FreeMemory_u64;

        /// <summary>
        /// Memory information: Total Phys
        /// </summary>
        public ulong TotalPhys_u64;

        /// <summary>
        /// Memory information: Used Phys
        /// </summary>
        public ulong UsedPhys_u64;

        /// <summary>
        /// Memory information: Free Phys
        /// </summary>
        public ulong FreePhys_u64;
    }

    /// <summary>
    /// VPN Session status
    /// </summary>
    public class VpnRpcSessionStatus
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// VPN session name
        /// </summary>
        public string Name_str;

        /// <summary>
        /// User name
        /// </summary>
        public string Username_str;

        /// <summary>
        /// Real user name which was used for the authentication
        /// </summary>
        public string RealUsername_str;

        /// <summary>
        /// Group name
        /// </summary>
        public string GroupName_str;

        /// <summary>
        /// Is Cascade Session
        /// </summary>
        public bool LinkMode_bool;

        /// <summary>
        /// Client IP address
        /// </summary>
        public string Client_Ip_Address_ip;

        /// <summary>
        /// Client host name
        /// </summary>
        [JsonProperty("SessionStatus_ClientHostName_str")]
        public string ClientHostName_str;

        /// <summary>
        /// Operation flag
        /// </summary>
        public bool Active_bool;

        /// <summary>
        /// Connected flag
        /// </summary>
        public bool Connected_bool;

        /// <summary>
        /// State of the client session
        /// </summary>
        public VpnRpcClientSessionStatus SessionStatus_u32;

        /// <summary>
        /// Server name
        /// </summary>
        public string ServerName_str;

        /// <summary>
        /// Port number of the server
        /// </summary>
        public uint ServerPort_u32;

        /// <summary>
        /// Server product name
        /// </summary>
        public string ServerProductName_str;

        /// <summary>
        /// Server product version
        /// </summary>
        public uint ServerProductVer_u32;

        /// <summary>
        /// Server product build number
        /// </summary>
        public uint ServerProductBuild_u32;

        /// <summary>
        /// Connection start time
        /// </summary>
        public DateTime StartTime_dt;

        /// <summary>
        /// Connection completion time of the first connection
        /// </summary>
        public DateTime FirstConnectionEstablisiedTime_dt;

        /// <summary>
        /// Connection completion time of this connection
        /// </summary>
        public DateTime CurrentConnectionEstablishTime_dt;

        /// <summary>
        /// Number of connections have been established so far
        /// </summary>
        public uint NumConnectionsEatablished_u32;

        /// <summary>
        /// Half-connection
        /// </summary>
        public bool HalfConnection_bool;

        /// <summary>
        /// VoIP / QoS
        /// </summary>
        public bool QoS_bool;

        /// <summary>
        /// Maximum number of the underlying TCP connections
        /// </summary>
        public uint MaxTcpConnections_u32;

        /// <summary>
        /// Number of current underlying TCP connections
        /// </summary>
        public uint NumTcpConnections_u32;

        /// <summary>
        /// Number of inbound underlying connections
        /// </summary>
        public uint NumTcpConnectionsUpload_u32;

        /// <summary>
        /// Number of outbound underlying connections
        /// </summary>
        public uint NumTcpConnectionsDownload_u32;

        /// <summary>
        /// Use of encryption
        /// </summary>
        public bool UseEncrypt_bool;

        /// <summary>
        /// Cipher algorithm name
        /// </summary>
        public string CipherName_str;

        /// <summary>
        /// Use of compression
        /// </summary>
        public bool UseCompress_bool;

        /// <summary>
        /// Is R-UDP session
        /// </summary>
        public bool IsRUDPSession_bool;

        /// <summary>
        /// Physical underlying communication protocol
        /// </summary>
        public string UnderlayProtocol_str;

        /// <summary>
        /// The UDP acceleration is enabled
        /// </summary>
        public bool IsUdpAccelerationEnabled_bool;

        /// <summary>
        /// Using the UDP acceleration function
        /// </summary>
        public bool IsUsingUdpAcceleration_bool;

        /// <summary>
        /// VPN session name
        /// </summary>
        public string SessionName_str;

        /// <summary>
        /// Connection name
        /// </summary>
        public string ConnectionName_str;

        /// <summary>
        /// Session key
        /// </summary>
        public byte[] SessionKey_bin;

        /// <summary>
        /// Total transmitted data size
        /// </summary>
        public ulong TotalSendSize_u64;

        /// <summary>
        /// Total received data size
        /// </summary>
        public ulong TotalRecvSize_u64;

        /// <summary>
        /// Total transmitted data size (no compression)
        /// </summary>
        public ulong TotalSendSizeReal_u64;

        /// <summary>
        /// Total received data size (no compression)
        /// </summary>
        public ulong TotalRecvSizeReal_u64;

        /// <summary>
        /// Is Bridge Mode
        /// </summary>
        public bool IsBridgeMode_bool;

        /// <summary>
        /// Is Monitor mode
        /// </summary>
        public bool IsMonitorMode_bool;

        /// <summary>
        /// VLAN ID
        /// </summary>
        public uint VLanId_u32;

        /// <summary>
        /// Client product name
        /// </summary>
        public string ClientProductName_str;

        /// <summary>
        /// Client version
        /// </summary>
        public uint ClientProductVer_u32;

        /// <summary>
        /// Client build number
        /// </summary>
        public uint ClientProductBuild_u32;

        /// <summary>
        /// Client OS name
        /// </summary>
        public string ClientOsName_str;

        /// <summary>
        /// Client OS version
        /// </summary>
        public string ClientOsVer_str;

        /// <summary>
        /// Client OS Product ID
        /// </summary>
        public string ClientOsProductId_str;

        /// <summary>
        /// Client host name
        /// </summary>
        public string ClientHostname_str;

        /// <summary>
        /// Unique ID
        /// </summary>
        public byte[] UniqueId_bin;
    }

    /// <summary>
    /// Set the special listener
    /// </summary>
    public class VpnRpcSpecialListener
    {
        /// <summary>
        /// The flag to activate the VPN over ICMP server function
        /// </summary>
        public bool VpnOverIcmpListener_bool;

        /// <summary>
        /// The flag to activate the VPN over DNS function
        /// </summary>
        public bool VpnOverDnsListener_bool;
    }

    /// <summary>
    /// Syslog configuration
    /// </summary>
    public enum VpnSyslogSaveType
    {
        /// <summary>
        /// Do not use syslog
        /// </summary>
        None = 0,

        /// <summary>
        /// Only server log
        /// </summary>
        ServerLog = 1,

        /// <summary>
        /// Server and Virtual HUB security log
        /// </summary>
        ServerAndHubSecurityLog = 2,

        /// <summary>
        /// Server, Virtual HUB security, and packet log
        /// </summary>
        ServerAndHubAllLog = 3,
    }

    /// <summary>
    /// Syslog configuration
    /// </summary>
    public class VpnSyslogSetting
    {
        /// <summary>
        /// The behavior of the syslog function
        /// </summary>
        public VpnSyslogSaveType SaveType_u32;

        /// <summary>
        /// Specify the host name or IP address of the syslog server
        /// </summary>
        public string Hostname_str;

        /// <summary>
        /// Specify the port number of the syslog server
        /// </summary>
        public uint Port_u32;
    }

    /// <summary>
    /// VPN Gate Server Config
    /// </summary>
    public class VpnVgsConfig
    {
        /// <summary>
        /// Active flag
        /// </summary>
        public bool IsEnabled_bool;

        /// <summary>
        /// Message
        /// </summary>
        public string Message_utf;

        /// <summary>
        /// Owner name
        /// </summary>
        public string Owner_utf;

        /// <summary>
        /// Abuse email
        /// </summary>
        public string Abuse_utf;

        /// <summary>
        /// Log save flag
        /// </summary>
        public bool NoLog_bool;

        /// <summary>
        /// Save log permanently
        /// </summary>
        public bool LogPermanent_bool;

        /// <summary>
        /// Enable the L2TP VPN function
        /// </summary>
        public bool EnableL2TP_bool;
    }

    /// <summary>
    /// Read a Log file
    /// </summary>
    public class VpnRpcReadLogFile
    {
        /// <summary>
        /// Server name
        /// </summary>
        public string ServerName_str;

        /// <summary>
        /// File Path
        /// </summary>
        public string FilePath_str;

        /// <summary>
        /// Offset to download. You have to call the ReadLogFile API multiple times to download the entire log file with requesting a part of the file by specifying the Offset_u32 field.
        /// </summary>
        public uint Offset_u32;

        /// <summary>
        /// Received buffer
        /// </summary>
        public byte[] Buffer_bin;
    }

    /// <summary>
    /// Rename link
    /// </summary>
    public class VpnRpcRenameLink
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// The old name of the cascade connection
        /// </summary>
        public string OldAccountName_utf;

        /// <summary>
        /// The new name of the cascade connection
        /// </summary>
        public string NewAccountName_utf;
    }

    /// <summary>
    /// Online or offline the HUB
    /// </summary>
    public class VpnRpcSetHubOnline
    {
        /// <summary>
        /// The Virtual Hub name
        /// </summary>
        public string HubName_str;

        /// <summary>
        /// Online / offline flag
        /// </summary>
        public bool Online_bool;
    }

    /// <summary>
    /// Set Password
    /// </summary>
    public class VpnRpcSetPassword
    {
        /// <summary>
        /// The plaintext password
        /// </summary>
        public string PlainTextPassword_str;
    }

}
