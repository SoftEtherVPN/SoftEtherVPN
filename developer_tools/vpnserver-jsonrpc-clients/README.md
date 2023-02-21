# SoftEther VPN Server JSON-RPC API Suite Document
This reference describes all JSON-RPC functions available on SoftEther VPN Server.


You can access to the latest [SoftEther VPN Server JSON-RPC Document on GitHub](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/).


## What is SoftEther VPN Server JSON-RPC API Suite?
The API Suite allows you to easily develop your original SoftEther VPN Server management application to control the VPN Server (e.g. creating users, adding Virtual Hubs, disconnecting a specified VPN sessions).

  - Almost all control APIs, which the VPN Server provides, are available as JSON-RPC API.
  - You can write your own VPN Server management application in your favorite languages (JavaScript, TypeScript, Java, Python, Ruby, C#, ... etc.)
  - If you are planning to develop your own VPN cloud service, the JSON-RPC API is the best choice to realize the automated operations for the VPN Server.
  - No need to use any specific API client library since all APIs are provided on the [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification). You can use your favorite JSON and HTTPS client library to call any of all APIs in your pure runtime environment.
  - Also, the SoftEther VPN Project provides high-quality JSON-RPC client stub libraries which define all of the API client stub codes. These libraries are written in C#, JavaScript and TypeScript. [The Node.js Client Library for VPN Server RPC (vpnrpc)](https://www.npmjs.com/package/vpnrpc) package is also available.


## Principle

### Entry point
The entry point URL of JSON-RPC is:
```
https://<vpn_server_hostname>:<port>/api/
```

  - Older versions of SoftEther VPN before June 2019 don't support JSON-RPC APIs.
  - If you want to completely disable the JSON-RPC on your VPN Server, set the `DisableJsonRpcWebApi` variable to `true` on the `vpn_server.config`.


### JSON-RPC specification
You must use HTTPS 1.1 `POST` method to call each of JSON-RPC APIs.  
All APIs are based on the [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification).
  - JSON-RPC Notification is not supported.
  - JSON-RPC Batch is not supported.


### "vpnrpc": Node.js Client Library package for VPN Server JSON-RPC
If you are willing to develop your original JSON-RPC client for SoftEther VPN, you can use the [JavaScript Client Library for VPN Server RPC (vpnrpc)](https://www.npmjs.com/package/vpnrpc).

  - You can use the `vpnrpc` library in JavaScript for both web browsers (e.g. Chrome, FireFox or Edge) and Node.js.
  - As a sample code there is the [sample.ts](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-typescript/sample.ts) program in TypeScript. This sample calls all of available JSON-RPC APIs against the specified SoftEther VPN Server. (Note: This sample code is written in TypeScript.)

You can use the following command to download the `vpnrpc` library package with Node.js.
```
$ npm install --save-dev vpnrpc
```



### "vpnrpc.ts": TypeScript Client Library for VPN Server JSON-RPC
If you are willing to develop your original JSON-RPC client for SoftEther VPN, you can use the [TypeScript Client Library for VPN Server RPC (vpnrpc.ts)](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-typescript/).

  - You can use the [vpnrpc.ts](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-typescript/vpnrpc.ts) library in TypeScript / JavaScript for both web browsers (e.g. Chrome, FireFox or Edge) and Node.js.
  - As a sample code there is the [sample.ts](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-typescript/sample.ts) program in TypeScript. This sample calls one by one all of available JSON-RPC APIs against the specified SoftEther VPN Server.


### "vpnserver-jsonrpc-client-csharp": C# Client Library for VPN Server JSON-RPC
If you are willing to develop your original JSON-RPC client for SoftEther VPN, you can use the [vpnserver-jsonrpc-client-csharp C# library](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-csharp/).

  - The [client library codes for C#](https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-csharp/rpc-stubs/) is written in pure C# 7.3. It works on .NET Core 2.1 or later on Windows, Linux and macOS. Very comfort with Visual Studio for both Windows or macOS.
  - As a sample code there is the [VpnServerRpcTest.cs](https://github.com/SoftEtherVPN/SoftEtherVPN/blob/master/developer_tools/vpnserver-jsonrpc-clients/vpnserver-jsonrpc-client-csharp/sample/VpnServerRpcTest.cs) program in C#. This sample calls one by one all of available JSON-RPC APIs against the specified SoftEther VPN Server.



### HTTPS Authentication
You must specify the following HTTPS custom headers for authentication on each of requests.


Value | Description
--- | ---
`X-VPNADMIN-HUBNAME` | The name of the Virtual Hub if you want to connect to the VPN Server as a Virtual Hub Admin Mode. Specify empty string if you want to connect to the VPN Server as the Entire VPN Server Admin Mode.
`X-VPNADMIN-PASSWORD` | Specify the administration password.


- You can omit the above HTTPS custom authentication headers if you are calling JSON-RPC APIs from the web browser which is already logged in to the VPN Server with HTTPS Basic Authentication. In such usage the credential of HTTPS Basic Authtication will be used.

***

## Table of contents
- [Test - Test RPC function](#test)
- [GetServerInfo - Get server information](#getserverinfo)
- [GetServerStatus - Get Current Server Status](#getserverstatus)
- [CreateListener - Create New TCP Listener](#createlistener)
- [EnumListener - Get List of TCP Listeners](#enumlistener)
- [DeleteListener - Delete TCP Listener](#deletelistener)
- [EnableListener - Enable / Disable TCP Listener](#enablelistener)
- [SetServerPassword - Set VPN Server Administrator Password](#setserverpassword)
- [SetFarmSetting - Set the VPN Server clustering configuration](#setfarmsetting)
- [GetFarmSetting - Get Clustering Configuration of Current VPN Server](#getfarmsetting)
- [GetFarmInfo - Get Cluster Member Information](#getfarminfo)
- [EnumFarmMember - Get List of Cluster Members](#enumfarmmember)
- [GetFarmConnectionStatus - Get Connection Status to Cluster Controller](#getfarmconnectionstatus)
- [SetServerCert - Set SSL Certificate and Private Key of VPN Server](#setservercert)
- [GetServerCert - Get SSL Certificate and Private Key of VPN Server](#getservercert)
- [GetServerCipher - Get the Encrypted Algorithm Used for VPN Communication](#getservercipher)
- [SetServerCipher - Set the Encrypted Algorithm Used for VPN Communication](#setservercipher)
- [CreateHub - Create New Virtual Hub](#createhub)
- [SetHub - Set the Virtual Hub configuration](#sethub)
- [GetHub - Get the Virtual Hub configuration](#gethub)
- [EnumHub - Get List of Virtual Hubs](#enumhub)
- [DeleteHub - Delete Virtual Hub](#deletehub)
- [GetHubRadius - Get Setting of RADIUS Server Used for User Authentication](#gethubradius)
- [SetHubRadius - Set RADIUS Server to use for User Authentication](#sethubradius)
- [EnumConnection - Get List of TCP Connections Connecting to the VPN Server](#enumconnection)
- [DisconnectConnection - Disconnect TCP Connections Connecting to the VPN Server](#disconnectconnection)
- [GetConnectionInfo - Get Information of TCP Connections Connecting to the VPN Server](#getconnectioninfo)
- [SetHubOnline - Switch Virtual Hub to Online or Offline](#sethubonline)
- [GetHubStatus - Get Current Status of Virtual Hub](#gethubstatus)
- [SetHubLog - Set the logging configuration of the Virtual Hub](#sethublog)
- [GetHubLog - Get the logging configuration of the Virtual Hub](#gethublog)
- [AddCa - Add Trusted CA Certificate](#addca)
- [EnumCa - Get List of Trusted CA Certificates](#enumca)
- [GetCa - Get Trusted CA Certificate](#getca)
- [DeleteCa - Delete Trusted CA Certificate](#deleteca)
- [CreateLink - Create New Cascade Connection](#createlink)
- [GetLink - Get the Cascade Connection Setting](#getlink)
- [SetLink - Change Existing Cascade Connection](#setlink)
- [EnumLink - Get List of Cascade Connections](#enumlink)
- [SetLinkOnline - Switch Cascade Connection to Online Status](#setlinkonline)
- [SetLinkOffline - Switch Cascade Connection to Offline Status](#setlinkoffline)
- [DeleteLink - Delete Cascade Connection Setting](#deletelink)
- [RenameLink - Change Name of Cascade Connection](#renamelink)
- [GetLinkStatus - Get Current Cascade Connection Status](#getlinkstatus)
- [AddAccess - Add Access List Rule](#addaccess)
- [DeleteAccess - Delete Rule from Access List](#deleteaccess)
- [EnumAccess - Get Access List Rule List](#enumaccess)
- [SetAccessList - Replace all access lists on a single bulk API call](#setaccesslist)
- [CreateUser - Create a user](#createuser)
- [SetUser - Change User Settings](#setuser)
- [GetUser - Get User Settings](#getuser)
- [DeleteUser - Delete a user](#deleteuser)
- [EnumUser - Get List of Users](#enumuser)
- [CreateGroup - Create Group](#creategroup)
- [SetGroup - Set group settings](#setgroup)
- [GetGroup - Get Group Setting (Sync mode)](#getgroup)
- [DeleteGroup - Delete User from Group](#deletegroup)
- [EnumGroup - Get List of Groups](#enumgroup)
- [EnumSession - Get List of Connected VPN Sessions](#enumsession)
- [GetSessionStatus - Get Session Status](#getsessionstatus)
- [DeleteSession - Disconnect Session](#deletesession)
- [EnumMacTable - Get the MAC Address Table Database](#enummactable)
- [DeleteMacTable - Delete MAC Address Table Entry](#deletemactable)
- [EnumIpTable - Get the IP Address Table Database](#enumiptable)
- [DeleteIpTable - Delete IP Address Table Entry](#deleteiptable)
- [SetKeep - Set the Keep Alive Internet Connection Function](#setkeep)
- [GetKeep - Get the Keep Alive Internet Connection Function](#getkeep)
- [EnableSecureNAT - Enable the Virtual NAT and DHCP Server Function (SecureNAT Function)](#enablesecurenat)
- [DisableSecureNAT - Disable the Virtual NAT and DHCP Server Function (SecureNAT Function)](#disablesecurenat)
- [SetSecureNATOption - Change Settings of SecureNAT Function](#setsecurenatoption)
- [GetSecureNATOption - Get Settings of SecureNAT Function](#getsecurenatoption)
- [EnumNAT - Get Virtual NAT Function Session Table of SecureNAT Function](#enumnat)
- [EnumDHCP - Get Virtual DHCP Server Function Lease Table of SecureNAT Function](#enumdhcp)
- [GetSecureNATStatus - Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function)](#getsecurenatstatus)
- [EnumEthernet - Get List of Network Adapters Usable as Local Bridge](#enumethernet)
- [AddLocalBridge - Create Local Bridge Connection](#addlocalbridge)
- [DeleteLocalBridge - Delete Local Bridge Connection](#deletelocalbridge)
- [EnumLocalBridge - Get List of Local Bridge Connection](#enumlocalbridge)
- [GetBridgeSupport - Get whether the localbridge function is supported on the current system](#getbridgesupport)
- [RebootServer - Reboot VPN Server Service](#rebootserver)
- [GetCaps - Get List of Server Functions / Capability](#getcaps)
- [GetConfig - Get the current configuration of the VPN Server](#getconfig)
- [SetConfig - Write Configuration File to VPN Server](#setconfig)
- [GetDefaultHubAdminOptions - Get Virtual Hub Administration Option default values](#getdefaulthubadminoptions)
- [GetHubAdminOptions - Get List of Virtual Hub Administration Options](#gethubadminoptions)
- [SetHubAdminOptions - Set Values of Virtual Hub Administration Options](#sethubadminoptions)
- [GetHubExtOptions - Get List of Virtual Hub Extended Options](#gethubextoptions)
- [SetHubExtOptions - Set a Value of Virtual Hub Extended Options](#sethubextoptions)
- [AddL3Switch - Define New Virtual Layer 3 Switch](#addl3switch)
- [DelL3Switch - Delete Virtual Layer 3 Switch](#dell3switch)
- [EnumL3Switch - Get List of Virtual Layer 3 Switches](#enuml3switch)
- [StartL3Switch - Start Virtual Layer 3 Switch Operation](#startl3switch)
- [StopL3Switch - Stop Virtual Layer 3 Switch Operation](#stopl3switch)
- [AddL3If - Add Virtual Interface to Virtual Layer 3 Switch](#addl3if)
- [DelL3If - Delete Virtual Interface of Virtual Layer 3 Switch](#dell3if)
- [EnumL3If - Get List of Interfaces Registered on the Virtual Layer 3 Switch](#enuml3if)
- [AddL3Table - Add Routing Table Entry for Virtual Layer 3 Switch](#addl3table)
- [DelL3Table - Delete Routing Table Entry of Virtual Layer 3 Switch](#dell3table)
- [EnumL3Table - Get List of Routing Tables of Virtual Layer 3 Switch](#enuml3table)
- [EnumCrl - Get List of Certificates Revocation List](#enumcrl)
- [AddCrl - Add a Revoked Certificate](#addcrl)
- [DelCrl - Delete a Revoked Certificate](#delcrl)
- [GetCrl - Get a Revoked Certificate](#getcrl)
- [SetCrl - Change Existing CRL (Certificate Revocation List) Entry](#setcrl)
- [SetAcList - Add Rule to Source IP Address Limit List](#setaclist)
- [GetAcList - Get List of Rule Items of Source IP Address Limit List](#getaclist)
- [EnumLogFile - Get List of Log Files](#enumlogfile)
- [ReadLogFile - Download a part of Log File](#readlogfile)
- [SetSysLog - Set syslog Send Function](#setsyslog)
- [GetSysLog - Get syslog Send Function](#getsyslog)
- [SetHubMsg - Set Today's Message of Virtual Hub](#sethubmsg)
- [GetHubMsg - Get Today's Message of Virtual Hub](#gethubmsg)
- [Crash - Raise a vital error on the VPN Server / Bridge to terminate the process forcefully](#crash)
- [GetAdminMsg - Get the message for administrators](#getadminmsg)
- [Flush - Save All Volatile Data of VPN Server / Bridge to the Configuration File](#flush)
- [SetIPsecServices - Enable or Disable IPsec VPN Server Function](#setipsecservices)
- [GetIPsecServices - Get the Current IPsec VPN Server Settings](#getipsecservices)
- [AddEtherIpId - Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices](#addetheripid)
- [GetEtherIpId - Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions](#getetheripid)
- [DeleteEtherIpId - Delete an EtherIP / L2TPv3 over IPsec Client Setting](#deleteetheripid)
- [EnumEtherIpId - Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions](#enumetheripid)
- [SetOpenVpnSstpConfig - Set Settings for OpenVPN Clone Server Function](#setopenvpnsstpconfig)
- [GetOpenVpnSstpConfig - Get the Current Settings of OpenVPN Clone Server Function](#getopenvpnsstpconfig)
- [GetDDnsClientStatus - Show the Current Status of Dynamic DNS Function](#getddnsclientstatus)
- [ChangeDDnsClientHostname - Set the Dynamic DNS Hostname](#changeddnsclienthostname)
- [RegenerateServerCert - Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server](#regenerateservercert)
- [MakeOpenVpnConfigFile - Generate a Sample Setting File for OpenVPN Client](#makeopenvpnconfigfile)
- [SetSpecialListener - Enable / Disable the VPN over ICMP / VPN over DNS Server Function](#setspeciallistener)
- [GetSpecialListener - Get Current Setting of the VPN over ICMP / VPN over DNS Function](#getspeciallistener)
- [GetAzureStatus - Show the current status of VPN Azure function](#getazurestatus)
- [SetAzureStatus - Enable / Disable VPN Azure Function](#setazurestatus)
- [GetDDnsInternetSettng - Get the Proxy Settings for Connecting to the DDNS server](#getddnsinternetsettng)
- [SetDDnsInternetSettng - Set the Proxy Settings for Connecting to the DDNS server](#setddnsinternetsettng)
- [SetVgsConfig - Set the VPN Gate Server Configuration](#setvgsconfig)
- [GetVgsConfig - Get the VPN Gate Server Configuration](#getvgsconfig)

***
<a id="test"></a>
## "Test" RPC API - Test RPC function
### Description
Test RPC function. Input any integer value to the IntValue_u32 field. Then the server will convert the integer to the string, and return the string in the StrValue_str field.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "Test",
  "params": {
    "IntValue_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="getserverinfo"></a>
## "GetServerInfo" RPC API - Get server information
### Description
Get server information. This allows you to obtain the server information of the currently connected VPN Server or VPN Bridge. Included in the server information are the version number, build number and build information. You can also obtain information on the current server operation mode and the information of operating system that the server is operating on.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetServerInfo",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerProductName_str": "serverproductname",
    "ServerVersionString_str": "serverversionstring",
    "ServerBuildInfoString_str": "serverbuildinfostring",
    "ServerVerInt_u32": 0,
    "ServerBuildInt_u32": 0,
    "ServerHostName_str": "serverhostname",
    "ServerType_u32": 0,
    "ServerBuildDate_dt": "2020-08-01T12:24:36.123",
    "ServerFamilyName_str": "serverfamilyname",
    "OsType_u32": 0,
    "OsServicePack_u32": 0,
    "OsSystemName_str": "ossystemname",
    "OsProductName_str": "osproductname",
    "OsVendorName_str": "osvendorname",
    "OsVersion_str": "osversion",
    "KernelName_str": "kernelname",
    "KernelVersion_str": "kernelversion"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerProductName_str` | `string` (ASCII) | Server product name
`ServerVersionString_str` | `string` (ASCII) | Server version string
`ServerBuildInfoString_str` | `string` (ASCII) | Server build information string
`ServerVerInt_u32` | `number` (uint32) | Server version integer value
`ServerBuildInt_u32` | `number` (uint32) | Server build number integer value
`ServerHostName_str` | `string` (ASCII) | Server host name
`ServerType_u32` | `number` (enum) | Type of server<BR>Values:<BR>`0`: Stand-alone server<BR>`1`: Farm controller server<BR>`2`: Farm member server
`ServerBuildDate_dt` | `Date` | Build date and time of the server
`ServerFamilyName_str` | `string` (ASCII) | Family name
`OsType_u32` | `number` (enum) | OS type<BR>Values:<BR>`1100`: Windows 95<BR>`1200`: Windows 98<BR>`1300`: Windows Me<BR>`1400`: Windows (unknown)<BR>`2100`: Windows NT 4.0 Workstation<BR>`2110`: Windows NT 4.0 Server<BR>`2111`: Windows NT 4.0 Server, Enterprise Edition<BR>`2112`: Windows NT 4.0 Terminal Server<BR>`2113`: BackOffice Server 4.5<BR>`2114`: Small Business Server 4.5<BR>`2200`: Windows 2000 Professional<BR>`2211`: Windows 2000 Server<BR>`2212`: Windows 2000 Advanced Server<BR>`2213`: Windows 2000 Datacenter Server<BR>`2214`: BackOffice Server 2000<BR>`2215`: Small Business Server 2000<BR>`2300`: Windows XP Home Edition<BR>`2301`: Windows XP Professional<BR>`2410`: Windows Server 2003 Web Edition<BR>`2411`: Windows Server 2003 Standard Edition<BR>`2412`: Windows Server 2003 Enterprise Edition<BR>`2413`: Windows Server 2003 DataCenter Edition<BR>`2414`: BackOffice Server 2003<BR>`2415`: Small Business Server 2003<BR>`2500`: Windows Vista<BR>`2510`: Windows Server 2008<BR>`2600`: Windows 7<BR>`2610`: Windows Server 2008 R2<BR>`2700`: Windows 8<BR>`2710`: Windows Server 2012<BR>`2701`: Windows 8.1<BR>`2711`: Windows Server 2012 R2<BR>`2702`: Windows 10<BR>`2712`: Windows Server 10<BR>`2800`: Windows 11 or later<BR>`2810`: Windows Server 11 or later<BR>`3000`: Unknown UNIX<BR>`3100`: Linux<BR>`3200`: Solaris<BR>`3300`: Cygwin<BR>`3400`: BSD<BR>`3500`: MacOS X
`OsServicePack_u32` | `number` (uint32) | Service pack number
`OsSystemName_str` | `string` (ASCII) | OS system name
`OsProductName_str` | `string` (ASCII) | OS product name
`OsVendorName_str` | `string` (ASCII) | OS vendor name
`OsVersion_str` | `string` (ASCII) | OS version
`KernelName_str` | `string` (ASCII) | Kernel name
`KernelVersion_str` | `string` (ASCII) | Kernel version

***
<a id="getserverstatus"></a>
## "GetServerStatus" RPC API - Get Current Server Status
### Description
Get Current Server Status. This allows you to obtain in real-time the current status of the currently connected VPN Server or VPN Bridge. You can get statistical information on data communication and the number of different kinds of objects that exist on the server. You can get information on how much memory is being used on the current computer by the OS.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetServerStatus",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerType_u32": 0,
    "NumTcpConnections_u32": 0,
    "NumTcpConnectionsLocal_u32": 0,
    "NumTcpConnectionsRemote_u32": 0,
    "NumHubTotal_u32": 0,
    "NumHubStandalone_u32": 0,
    "NumHubStatic_u32": 0,
    "NumHubDynamic_u32": 0,
    "NumSessionsTotal_u32": 0,
    "NumSessionsLocal_u32": 0,
    "NumSessionsRemote_u32": 0,
    "NumMacTables_u32": 0,
    "NumIpTables_u32": 0,
    "NumUsers_u32": 0,
    "NumGroups_u32": 0,
    "AssignedBridgeLicenses_u32": 0,
    "AssignedClientLicenses_u32": 0,
    "AssignedBridgeLicensesTotal_u32": 0,
    "AssignedClientLicensesTotal_u32": 0,
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "CurrentTime_dt": "2020-08-01T12:24:36.123",
    "CurrentTick_u64": 0,
    "StartTime_dt": "2020-08-01T12:24:36.123",
    "TotalMemory_u64": 0,
    "UsedMemory_u64": 0,
    "FreeMemory_u64": 0,
    "TotalPhys_u64": 0,
    "UsedPhys_u64": 0,
    "FreePhys_u64": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerType_u32` | `number` (enum) | Type of server<BR>Values:<BR>`0`: Stand-alone server<BR>`1`: Farm controller server<BR>`2`: Farm member server
`NumTcpConnections_u32` | `number` (uint32) | Total number of TCP connections
`NumTcpConnectionsLocal_u32` | `number` (uint32) | Number of Local TCP connections
`NumTcpConnectionsRemote_u32` | `number` (uint32) | Number of remote TCP connections
`NumHubTotal_u32` | `number` (uint32) | Total number of HUBs
`NumHubStandalone_u32` | `number` (uint32) | Nymber of stand-alone HUB
`NumHubStatic_u32` | `number` (uint32) | Number of static HUBs
`NumHubDynamic_u32` | `number` (uint32) | Number of Dynamic HUBs
`NumSessionsTotal_u32` | `number` (uint32) | Total number of sessions
`NumSessionsLocal_u32` | `number` (uint32) | Number of local VPN sessions
`NumSessionsRemote_u32` | `number` (uint32) | The number of remote sessions
`NumMacTables_u32` | `number` (uint32) | Number of MAC table entries (total sum of all Virtual Hubs)
`NumIpTables_u32` | `number` (uint32) | Number of IP table entries (total sum of all Virtual Hubs)
`NumUsers_u32` | `number` (uint32) | Number of users (total sum of all Virtual Hubs)
`NumGroups_u32` | `number` (uint32) | Number of groups (total sum of all Virtual Hubs)
`AssignedBridgeLicenses_u32` | `number` (uint32) | Number of assigned bridge licenses (Useful to make a commercial version)
`AssignedClientLicenses_u32` | `number` (uint32) | Number of assigned client licenses (Useful to make a commercial version)
`AssignedBridgeLicensesTotal_u32` | `number` (uint32) | Number of Assigned bridge license (cluster-wide), useful to make a commercial version
`AssignedClientLicensesTotal_u32` | `number` (uint32) | Number of assigned client licenses (cluster-wide), useful to make a commercial version
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`CurrentTime_dt` | `Date` | Current time
`CurrentTick_u64` | `number` (uint64) | 64 bit High-Precision Logical System Clock
`StartTime_dt` | `Date` | VPN Server Start-up time
`TotalMemory_u64` | `number` (uint64) | Memory information: Total Memory
`UsedMemory_u64` | `number` (uint64) | Memory information: Used Memory
`FreeMemory_u64` | `number` (uint64) | Memory information: Free Memory
`TotalPhys_u64` | `number` (uint64) | Memory information: Total Phys
`UsedPhys_u64` | `number` (uint64) | Memory information: Used Phys
`FreePhys_u64` | `number` (uint64) | Memory information: Free Phys

***
<a id="createlistener"></a>
## "CreateListener" RPC API - Create New TCP Listener
### Description
Create New TCP Listener. This allows you to create a new TCP Listener on the server. By creating the TCP Listener the server starts listening for a connection from clients at the specified TCP/IP port number. A TCP Listener that has been created can be deleted by the DeleteListener API. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To execute this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "CreateListener",
  "params": {
    "Port_u32": 0,
    "Enable_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Port_u32": 0,
    "Enable_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Port_u32` | `number` (uint32) | Port number (Range: 1 - 65535)
`Enable_bool` | `boolean` | Active state

***
<a id="enumlistener"></a>
## "EnumListener" RPC API - Get List of TCP Listeners
### Description
Get List of TCP Listeners. This allows you to get a list of TCP listeners registered on the current server. You can obtain information on whether the various TCP listeners have a status of operating or error. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumListener",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ListenerList": [
      {
        "Ports_u32": 0,
        "Enables_bool": false,
        "Errors_bool": false
      },
      {
        "Ports_u32": 0,
        "Enables_bool": false,
        "Errors_bool": false
      },
      {
        "Ports_u32": 0,
        "Enables_bool": false,
        "Errors_bool": false
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ListenerList` | `Array object` | List of listener items
`Ports_u32` | `number` (uint32) | TCP port number (range: 1 - 65535)
`Enables_bool` | `boolean` | Active state
`Errors_bool` | `boolean` | The flag to indicate if the error occurred on the listener port

***
<a id="deletelistener"></a>
## "DeleteListener" RPC API - Delete TCP Listener
### Description
Delete TCP Listener. This allows you to delete a TCP Listener that's registered on the server. When the TCP Listener is in a state of operation, the listener will automatically be deleted when its operation stops. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteListener",
  "params": {
    "Port_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Port_u32": 0,
    "Enable_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Port_u32` | `number` (uint32) | Port number (Range: 1 - 65535)
`Enable_bool` | `boolean` | Active state

***
<a id="enablelistener"></a>
## "EnableListener" RPC API - Enable / Disable TCP Listener
### Description
Enable / Disable TCP Listener. This starts or stops the operation of TCP Listeners registered on the current server. You can also get a list of TCP Listeners currently registered by using the EnumListener API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnableListener",
  "params": {
    "Port_u32": 0,
    "Enable_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Port_u32": 0,
    "Enable_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Port_u32` | `number` (uint32) | Port number (Range: 1 - 65535)
`Enable_bool` | `boolean` | Active state

***
<a id="setserverpassword"></a>
## "SetServerPassword" RPC API - Set VPN Server Administrator Password
### Description
Set VPN Server Administrator Password. This sets the VPN Server administrator password. You can specify the password as a parameter. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetServerPassword",
  "params": {
    "PlainTextPassword_str": "plaintextpassword"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "PlainTextPassword_str": "plaintextpassword"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`PlainTextPassword_str` | `string` (ASCII) | The plaintext password

***
<a id="setfarmsetting"></a>
## "SetFarmSetting" RPC API - Set the VPN Server clustering configuration
### Description
Set the VPN Server clustering configuration. Use this to set the VPN Server type as Standalone Server, Cluster Controller Server or Cluster Member Server. Standalone server means a VPN Server that does not belong to any cluster in its current state. When VPN Server is installed, by default it will be in standalone server mode. Unless you have particular plans to configure a cluster, we recommend the VPN Server be operated in standalone mode. A cluster controller is the central computer of all member servers of a cluster in the case where a clustering environment is made up of multiple VPN Servers. Multiple cluster members can be added to the cluster as required. A cluster requires one computer to serve this role. The other cluster member servers that are configured in the same cluster begin operation as a cluster member by connecting to the cluster controller. To call this API, you must have VPN Server administrator privileges. Also, when this API is executed, VPN Server will automatically restart. This API cannot be called on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetFarmSetting",
  "params": {
    "ServerType_u32": 0,
    "NumPort_u32": 0,
    "Ports_u32": [
      1,
      2,
      3
    ],
    "PublicIp_ip": "192.168.0.1",
    "ControllerName_str": "controllername",
    "ControllerPort_u32": 0,
    "MemberPasswordPlaintext_str": "memberpasswordplaintext",
    "Weight_u32": 0,
    "ControllerOnly_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerType_u32": 0,
    "NumPort_u32": 0,
    "Ports_u32": [
      1,
      2,
      3
    ],
    "PublicIp_ip": "192.168.0.1",
    "ControllerName_str": "controllername",
    "ControllerPort_u32": 0,
    "MemberPasswordPlaintext_str": "memberpasswordplaintext",
    "Weight_u32": 0,
    "ControllerOnly_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerType_u32` | `number` (enum) | Type of server<BR>Values:<BR>`0`: Stand-alone server<BR>`1`: Farm controller server<BR>`2`: Farm member server
`NumPort_u32` | `number` (uint32) | Valid only for Cluster Member servers. Number of the Ports_u32 element.
`Ports_u32` | `number[]` (uint32) | Valid only for Cluster Member servers. Specify the list of public port numbers on this server. The list must have at least one public port number set, and it is also possible to set multiple public port numbers.
`PublicIp_ip` | `string` (IP address) | Valid only for Cluster Member servers. Specify the public IP address of this server. If you wish to leave public IP address unspecified, specify the empty string. When a public IP address is not specified, the IP address of the network interface used when connecting to the cluster controller will be automatically used.
`ControllerName_str` | `string` (ASCII) | Valid only for Cluster Member servers. Specify the host name or IP address of the destination cluster controller.
`ControllerPort_u32` | `number` (uint32) | Valid only for Cluster Member servers. Specify the TCP port number of the destination cluster controller.
`MemberPasswordPlaintext_str` | `string` (ASCII) | Valid only for Cluster Member servers. Specify the password required to connect to the destination controller. It needs to be the same as an administrator password on the destination controller.
`Weight_u32` | `number` (uint32) | This sets a value for the performance standard ratio of this VPN Server. This is the standard value for when load balancing is performed in the cluster. For example, making only one machine 200 while the other members have a status of 100, will regulate that machine to receive twice as many connections as the other members. Specify 1 or higher for the value. If this parameter is left unspecified, 100 will be used.
`ControllerOnly_bool` | `boolean` | Valid only for Cluster Controller server. By specifying true, the VPN Server will operate only as a controller on the cluster and it will always distribute general VPN Client connections to members other than itself. This function is used in high-load environments.

***
<a id="getfarmsetting"></a>
## "GetFarmSetting" RPC API - Get Clustering Configuration of Current VPN Server
### Description
Get Clustering Configuration of Current VPN Server. You can use this to acquire the clustering configuration of the current VPN Server. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetFarmSetting",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerType_u32": 0,
    "NumPort_u32": 0,
    "Ports_u32": [
      1,
      2,
      3
    ],
    "PublicIp_ip": "192.168.0.1",
    "ControllerName_str": "controllername",
    "ControllerPort_u32": 0,
    "MemberPasswordPlaintext_str": "memberpasswordplaintext",
    "Weight_u32": 0,
    "ControllerOnly_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerType_u32` | `number` (enum) | Type of server<BR>Values:<BR>`0`: Stand-alone server<BR>`1`: Farm controller server<BR>`2`: Farm member server
`NumPort_u32` | `number` (uint32) | Valid only for Cluster Member servers. Number of the Ports_u32 element.
`Ports_u32` | `number[]` (uint32) | Valid only for Cluster Member servers. Specify the list of public port numbers on this server. The list must have at least one public port number set, and it is also possible to set multiple public port numbers.
`PublicIp_ip` | `string` (IP address) | Valid only for Cluster Member servers. Specify the public IP address of this server. If you wish to leave public IP address unspecified, specify the empty string. When a public IP address is not specified, the IP address of the network interface used when connecting to the cluster controller will be automatically used.
`ControllerName_str` | `string` (ASCII) | Valid only for Cluster Member servers. Specify the host name or IP address of the destination cluster controller.
`ControllerPort_u32` | `number` (uint32) | Valid only for Cluster Member servers. Specify the TCP port number of the destination cluster controller.
`MemberPasswordPlaintext_str` | `string` (ASCII) | Valid only for Cluster Member servers. Specify the password required to connect to the destination controller. It needs to be the same as an administrator password on the destination controller.
`Weight_u32` | `number` (uint32) | This sets a value for the performance standard ratio of this VPN Server. This is the standard value for when load balancing is performed in the cluster. For example, making only one machine 200 while the other members have a status of 100, will regulate that machine to receive twice as many connections as the other members. Specify 1 or higher for the value. If this parameter is left unspecified, 100 will be used.
`ControllerOnly_bool` | `boolean` | Valid only for Cluster Controller server. By specifying true, the VPN Server will operate only as a controller on the cluster and it will always distribute general VPN Client connections to members other than itself. This function is used in high-load environments.

***
<a id="getfarminfo"></a>
## "GetFarmInfo" RPC API - Get Cluster Member Information
### Description
Get Cluster Member Information. When the VPN Server is operating as a cluster controller, you can get information on cluster member servers on that cluster by specifying the IDs of the member servers. You can get the following information about the specified cluster member server: Server Type, Time Connection has been Established, IP Address, Host Name, Points, Public Port List, Number of Operating Virtual Hubs, First Virtual Hub, Number of Sessions and Number of TCP Connections. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetFarmInfo",
  "params": {
    "Id_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Id_u32": 0,
    "Controller_bool": false,
    "ConnectedTime_dt": "2020-08-01T12:24:36.123",
    "Ip_ip": "192.168.0.1",
    "Hostname_str": "hostname",
    "Point_u32": 0,
    "NumPort_u32": 0,
    "Ports_u32": [
      1,
      2,
      3
    ],
    "ServerCert_bin": "SGVsbG8gV29ybGQ=",
    "NumFarmHub_u32": 0,
    "HubsList": [
      {
        "HubName_str": "hubname",
        "DynamicHub_bool": false
      },
      {
        "HubName_str": "hubname",
        "DynamicHub_bool": false
      },
      {
        "HubName_str": "hubname",
        "DynamicHub_bool": false
      }
    ],
    "NumSessions_u32": 0,
    "NumTcpConnections_u32": 0,
    "Weight_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Id_u32` | `number` (uint32) | ID
`Controller_bool` | `boolean` | The flag if the server is Cluster Controller (false: Cluster Member servers)
`ConnectedTime_dt` | `Date` | Connection Established Time
`Ip_ip` | `string` (IP address) | IP address
`Hostname_str` | `string` (ASCII) | Host name
`Point_u32` | `number` (uint32) | Point
`NumPort_u32` | `number` (uint32) | Number of Public Ports
`Ports_u32` | `number[]` (uint32) | Public Ports
`ServerCert_bin` | `string` (Base64 binary) | Server certificate
`NumFarmHub_u32` | `number` (uint32) | Number of farm HUB
`HubsList` | `Array object` | The hosted Virtual Hub list
`NumSessions_u32` | `number` (uint32) | Number of hosted VPN sessions
`NumTcpConnections_u32` | `number` (uint32) | Number of TCP connections
`Weight_u32` | `number` (uint32) | Performance Standard Ratio
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`DynamicHub_bool` | `boolean` | Dynamic HUB

***
<a id="enumfarmmember"></a>
## "EnumFarmMember" RPC API - Get List of Cluster Members
### Description
Get List of Cluster Members. Use this API when the VPN Server is operating as a cluster controller to get a list of the cluster member servers on the same cluster, including the cluster controller itself. For each member, the following information is also listed: Type, Connection Start, Host Name, Points, Number of Session, Number of TCP Connections, Number of Operating Virtual Hubs, Using Client Connection License and Using Bridge Connection License. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumFarmMember",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "NumFarm_u32": 0,
    "FarmMemberList": [
      {
        "Id_u32": 0,
        "Controller_bool": false,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Ip_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "Point_u32": 0,
        "NumSessions_u32": 0,
        "NumTcpConnections_u32": 0,
        "NumHubs_u32": 0,
        "AssignedClientLicense_u32": 0,
        "AssignedBridgeLicense_u32": 0
      },
      {
        "Id_u32": 0,
        "Controller_bool": false,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Ip_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "Point_u32": 0,
        "NumSessions_u32": 0,
        "NumTcpConnections_u32": 0,
        "NumHubs_u32": 0,
        "AssignedClientLicense_u32": 0,
        "AssignedBridgeLicense_u32": 0
      },
      {
        "Id_u32": 0,
        "Controller_bool": false,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Ip_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "Point_u32": 0,
        "NumSessions_u32": 0,
        "NumTcpConnections_u32": 0,
        "NumHubs_u32": 0,
        "AssignedClientLicense_u32": 0,
        "AssignedBridgeLicense_u32": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`NumFarm_u32` | `number` (uint32) | Number of Cluster Members
`FarmMemberList` | `Array object` | Cluster Members list
`Id_u32` | `number` (uint32) | ID
`Controller_bool` | `boolean` | Controller
`ConnectedTime_dt` | `Date` | Connection time
`Ip_ip` | `string` (IP address) | IP address
`Hostname_str` | `string` (ASCII) | Host name
`Point_u32` | `number` (uint32) | Point
`NumSessions_u32` | `number` (uint32) | Number of sessions
`NumTcpConnections_u32` | `number` (uint32) | Number of TCP connections
`NumHubs_u32` | `number` (uint32) | Number of HUBs
`AssignedClientLicense_u32` | `number` (uint32) | Number of assigned client licenses
`AssignedBridgeLicense_u32` | `number` (uint32) | Number of assigned bridge licenses

***
<a id="getfarmconnectionstatus"></a>
## "GetFarmConnectionStatus" RPC API - Get Connection Status to Cluster Controller
### Description
Get Connection Status to Cluster Controller. Use this API when the VPN Server is operating as a cluster controller to get the status of connection to the cluster controller. You can get the following information: Controller IP Address, Port Number, Connection Status, Connection Start Time, First Connection Established Time, Current Connection Established Time, Number of Connection Attempts, Number of Successful Connections, Number of Failed Connections. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetFarmConnectionStatus",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Ip_ip": "192.168.0.1",
    "Port_u32": 0,
    "Online_bool": false,
    "LastError_u32": 0,
    "StartedTime_dt": "2020-08-01T12:24:36.123",
    "FirstConnectedTime_dt": "2020-08-01T12:24:36.123",
    "CurrentConnectedTime_dt": "2020-08-01T12:24:36.123",
    "NumTry_u32": 0,
    "NumConnected_u32": 0,
    "NumFailed_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Ip_ip` | `string` (IP address) | IP address
`Port_u32` | `number` (uint32) | Port number
`Online_bool` | `boolean` | Online state
`LastError_u32` | `number` (uint32) | Last error code
`StartedTime_dt` | `Date` | Connection start time
`FirstConnectedTime_dt` | `Date` | First connection time
`CurrentConnectedTime_dt` | `Date` | Connection time of this time
`NumTry_u32` | `number` (uint32) | Number of retries
`NumConnected_u32` | `number` (uint32) | Number of connection count
`NumFailed_u32` | `number` (uint32) | Connection failure count

***
<a id="setservercert"></a>
## "SetServerCert" RPC API - Set SSL Certificate and Private Key of VPN Server
### Description
Set SSL Certificate and Private Key of VPN Server. You can set the SSL certificate that the VPN Server provides to the connected client and the private key for that certificate. The certificate must be in X.509 format and the private key must be Base 64 encoded format. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetServerCert",
  "params": {
    "Cert_bin": "SGVsbG8gV29ybGQ=",
    "Key_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Cert_bin": "SGVsbG8gV29ybGQ=",
    "Key_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Cert_bin` | `string` (Base64 binary) | The body of the certificate
`Key_bin` | `string` (Base64 binary) | The body of the private key

***
<a id="getservercert"></a>
## "GetServerCert" RPC API - Get SSL Certificate and Private Key of VPN Server
### Description
Get SSL Certificate and Private Key of VPN Server. Use this to get the SSL certificate private key that the VPN Server provides to the connected client. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetServerCert",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Cert_bin": "SGVsbG8gV29ybGQ=",
    "Key_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Cert_bin` | `string` (Base64 binary) | The body of the certificate
`Key_bin` | `string` (Base64 binary) | The body of the private key

***
<a id="getservercipher"></a>
## "GetServerCipher" RPC API - Get the Encrypted Algorithm Used for VPN Communication
### Description
Get the Encrypted Algorithm Used for VPN Communication. Use this API to get the current setting of the algorithm used for the electronic signature and encrypted for SSL connection to be used for communication between the VPN Server and the connected client and the list of algorithms that can be used on the VPN Server.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetServerCipher",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "String_str": "string"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`String_str` | `string` (ASCII) | A string value

***
<a id="setservercipher"></a>
## "SetServerCipher" RPC API - Set the Encrypted Algorithm Used for VPN Communication
### Description
Set the Encrypted Algorithm Used for VPN Communication. Use this API to set the algorithm used for the electronic signature and encrypted for SSL connections to be used for communication between the VPN Server and the connected client. By specifying the algorithm name, the specified algorithm will be used later between the VPN Client and VPN Bridge connected to this server and the data will be encrypted. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetServerCipher",
  "params": {
    "String_str": "string"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "String_str": "string"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`String_str` | `string` (ASCII) | A string value

***
<a id="createhub"></a>
## "CreateHub" RPC API - Create New Virtual Hub
### Description
Create New Virtual Hub. Use this to create a new Virtual Hub on the VPN Server. The created Virtual Hub will begin operation immediately. When the VPN Server is operating on a cluster, this API is only valid for the cluster controller. Also, the new Virtual Hub will operate as a dynamic Virtual Hub. You can change it to a static Virtual Hub by using the SetHub API. To get a list of Virtual Hubs that are already on the VPN Server, use the EnumHub API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "CreateHub",
  "params": {
    "HubName_str": "hubname",
    "AdminPasswordPlainText_str": "adminpasswordplaintext",
    "Online_bool": false,
    "MaxSession_u32": 0,
    "NoEnum_bool": false,
    "HubType_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminPasswordPlainText_str": "adminpasswordplaintext",
    "Online_bool": false,
    "MaxSession_u32": 0,
    "NoEnum_bool": false,
    "HubType_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to create / update.
`AdminPasswordPlainText_str` | `string` (ASCII) | Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password.
`Online_bool` | `boolean` | Online flag
`MaxSession_u32` | `number` (uint32) | Maximum number of VPN sessions
`NoEnum_bool` | `boolean` | No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server.
`HubType_u32` | `number` (enum) | Type of the Virtual Hub (Valid only for Clustered VPN Servers)<BR>Values:<BR>`0`: Stand-alone HUB<BR>`1`: Static HUB<BR>`2`: Dynamic HUB

***
<a id="sethub"></a>
## "SetHub" RPC API - Set the Virtual Hub configuration
### Description
Set the Virtual Hub configuration. You can call this API to change the configuration of the specified Virtual Hub. You can set the Virtual Hub online or offline. You can set the maximum number of sessions that can be concurrently connected to the Virtual Hub that is currently being managed. You can set the Virtual Hub administrator password. You can set other parameters for the Virtual Hub. Before call this API, you need to obtain the latest state of the Virtual Hub by using the GetHub API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHub",
  "params": {
    "HubName_str": "hubname",
    "AdminPasswordPlainText_str": "adminpasswordplaintext",
    "Online_bool": false,
    "MaxSession_u32": 0,
    "NoEnum_bool": false,
    "HubType_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminPasswordPlainText_str": "adminpasswordplaintext",
    "Online_bool": false,
    "MaxSession_u32": 0,
    "NoEnum_bool": false,
    "HubType_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to create / update.
`AdminPasswordPlainText_str` | `string` (ASCII) | Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password.
`Online_bool` | `boolean` | Online flag
`MaxSession_u32` | `number` (uint32) | Maximum number of VPN sessions
`NoEnum_bool` | `boolean` | No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server.
`HubType_u32` | `number` (enum) | Type of the Virtual Hub (Valid only for Clustered VPN Servers)<BR>Values:<BR>`0`: Stand-alone HUB<BR>`1`: Static HUB<BR>`2`: Dynamic HUB

***
<a id="gethub"></a>
## "GetHub" RPC API - Get the Virtual Hub configuration
### Description
Get the Virtual Hub configuration. You can call this API to get the current configuration of the specified Virtual Hub. To change the configuration of the Virtual Hub, call the SetHub API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHub",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminPasswordPlainText_str": "adminpasswordplaintext",
    "Online_bool": false,
    "MaxSession_u32": 0,
    "NoEnum_bool": false,
    "HubType_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to create / update.
`AdminPasswordPlainText_str` | `string` (ASCII) | Specify an administrator password when the administrator password is going to be set for the Virtual Hub. On the update, leave it to empty string if you don't want to change the password.
`Online_bool` | `boolean` | Online flag
`MaxSession_u32` | `number` (uint32) | Maximum number of VPN sessions
`NoEnum_bool` | `boolean` | No Enum flag. By enabling this option, the VPN Client user will be unable to enumerate this Virtual Hub even if they send a Virtual Hub enumeration request to the VPN Server.
`HubType_u32` | `number` (enum) | Type of the Virtual Hub (Valid only for Clustered VPN Servers)<BR>Values:<BR>`0`: Stand-alone HUB<BR>`1`: Static HUB<BR>`2`: Dynamic HUB

***
<a id="enumhub"></a>
## "EnumHub" RPC API - Get List of Virtual Hubs
### Description
Get List of Virtual Hubs. Use this to get a list of existing Virtual Hubs on the VPN Server. For each Virtual Hub, you can get the following information: Virtual Hub Name, Status, Type, Number of Users, Number of Groups, Number of Sessions, Number of MAC Tables, Number of IP Tables, Number of Logins, Last Login, and Last Communication. Note that when connecting in Virtual Hub Admin Mode, if in the options of a Virtual Hub that you do not have administrator privileges for, the option Don't Enumerate this Virtual Hub for Anonymous Users is enabled then that Virtual Hub will not be enumerated. If you are connected in Server Admin Mode, then the list of all Virtual Hubs will be displayed. When connecting to and managing a non-cluster-controller cluster member of a clustering environment, only the Virtual Hub currently being hosted by that VPN Server will be displayed. When connecting to a cluster controller for administration purposes, all the Virtual Hubs will be displayed.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumHub",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "NumHub_u32": 0,
    "HubList": [
      {
        "HubName_str": "hubname",
        "Online_bool": false,
        "HubType_u32": 0,
        "NumUsers_u32": 0,
        "NumGroups_u32": 0,
        "NumSessions_u32": 0,
        "NumMacTables_u32": 0,
        "NumIpTables_u32": 0,
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "NumLogin_u32": 0,
        "IsTrafficFilled_bool": false,
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      },
      {
        "HubName_str": "hubname",
        "Online_bool": false,
        "HubType_u32": 0,
        "NumUsers_u32": 0,
        "NumGroups_u32": 0,
        "NumSessions_u32": 0,
        "NumMacTables_u32": 0,
        "NumIpTables_u32": 0,
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "NumLogin_u32": 0,
        "IsTrafficFilled_bool": false,
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      },
      {
        "HubName_str": "hubname",
        "Online_bool": false,
        "HubType_u32": 0,
        "NumUsers_u32": 0,
        "NumGroups_u32": 0,
        "NumSessions_u32": 0,
        "NumMacTables_u32": 0,
        "NumIpTables_u32": 0,
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "NumLogin_u32": 0,
        "IsTrafficFilled_bool": false,
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`NumHub_u32` | `number` (uint32) | Number of Virtual Hubs
`HubList` | `Array object` | Virtual Hubs
`HubName_str` | `string` (ASCII) | The name of the Virtual Hub
`Online_bool` | `boolean` | Online state
`HubType_u32` | `number` (enum) | Type of HUB (Valid only for Clustered VPN Servers)<BR>Values:<BR>`0`: Stand-alone HUB<BR>`1`: Static HUB<BR>`2`: Dynamic HUB
`NumUsers_u32` | `number` (uint32) | Number of users
`NumGroups_u32` | `number` (uint32) | Number of registered groups
`NumSessions_u32` | `number` (uint32) | Number of registered sessions
`NumMacTables_u32` | `number` (uint32) | Number of current MAC table entries
`NumIpTables_u32` | `number` (uint32) | Number of current IP table entries
`LastCommTime_dt` | `Date` | Last communication date and time
`LastLoginTime_dt` | `Date` | Last login date and time
`CreatedTime_dt` | `Date` | Creation date and time
`NumLogin_u32` | `number` (uint32) | Number of accumulated logins
`IsTrafficFilled_bool` | `boolean` | Whether the traffic information is provided
`Ex.Recv.BroadcastBytes_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Ex.Recv.BroadcastCount_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Ex.Recv.UnicastBytes_u64` | `number` (uint64) | Unicast count (Recv)
`Ex.Recv.UnicastCount_u64` | `number` (uint64) | Unicast bytes (Recv)
`Ex.Send.BroadcastBytes_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Ex.Send.BroadcastCount_u64` | `number` (uint64) | Broadcast bytes (Send)
`Ex.Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Ex.Send.UnicastCount_u64` | `number` (uint64) | Unicast bytes (Send)

***
<a id="deletehub"></a>
## "DeleteHub" RPC API - Delete Virtual Hub
### Description
Delete Virtual Hub. Use this to delete an existing Virtual Hub on the VPN Server. If you delete the Virtual Hub, all sessions that are currently connected to the Virtual Hub will be disconnected and new sessions will be unable to connect to the Virtual Hub. Also, this will also delete all the Hub settings, user objects, group objects, certificates and Cascade Connections. Once you delete the Virtual Hub, it cannot be recovered. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Servers that are operating as a VPN Bridge or cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteHub",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name

***
<a id="gethubradius"></a>
## "GetHubRadius" RPC API - Get Setting of RADIUS Server Used for User Authentication
### Description
Get Setting of RADIUS Server Used for User Authentication. Use this to get the current settings for the RADIUS server used when a user connects to the currently managed Virtual Hub using RADIUS Server Authentication Mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubRadius",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "RadiusServerName_str": "radiusservername",
    "RadiusPort_u32": 0,
    "RadiusSecret_str": "radiussecret",
    "RadiusRetryInterval_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`RadiusServerName_str` | `string` (ASCII) | RADIUS server name
`RadiusPort_u32` | `number` (uint32) | RADIUS port number
`RadiusSecret_str` | `string` (ASCII) | Secret key
`RadiusRetryInterval_u32` | `number` (uint32) | Radius retry interval

***
<a id="sethubradius"></a>
## "SetHubRadius" RPC API - Set RADIUS Server to use for User Authentication
### Description
Set RADIUS Server to use for User Authentication. To accept users to the currently managed Virtual Hub in RADIUS server authentication mode, you can specify an external RADIUS server that confirms the user name and password. (You can specify multiple hostname by splitting with comma or semicolon.) The RADIUS server must be set to receive requests from IP addresses of this VPN Server. Also, authentication by Password Authentication Protocol (PAP) must be enabled. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubRadius",
  "params": {
    "HubName_str": "hubname",
    "RadiusServerName_str": "radiusservername",
    "RadiusPort_u32": 0,
    "RadiusSecret_str": "radiussecret",
    "RadiusRetryInterval_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "RadiusServerName_str": "radiusservername",
    "RadiusPort_u32": 0,
    "RadiusSecret_str": "radiussecret",
    "RadiusRetryInterval_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`RadiusServerName_str` | `string` (ASCII) | RADIUS server name
`RadiusPort_u32` | `number` (uint32) | RADIUS port number
`RadiusSecret_str` | `string` (ASCII) | Secret key
`RadiusRetryInterval_u32` | `number` (uint32) | Radius retry interval

***
<a id="enumconnection"></a>
## "EnumConnection" RPC API - Get List of TCP Connections Connecting to the VPN Server
### Description
Get List of TCP Connections Connecting to the VPN Server. Use this to get a list of TCP/IP connections that are currently connecting to the VPN Server. It does not display the TCP connections that have been established as VPN sessions. To get the list of TCP/IP connections that have been established as VPN sessions, you can use the EnumSession API. You can get the following: Connection Name, Connection Source, Connection Start and Type. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumConnection",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "NumConnection_u32": 0,
    "ConnectionList": [
      {
        "Name_str": "name",
        "Hostname_str": "hostname",
        "Ip_ip": "192.168.0.1",
        "Port_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Type_u32": 0
      },
      {
        "Name_str": "name",
        "Hostname_str": "hostname",
        "Ip_ip": "192.168.0.1",
        "Port_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Type_u32": 0
      },
      {
        "Name_str": "name",
        "Hostname_str": "hostname",
        "Ip_ip": "192.168.0.1",
        "Port_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Type_u32": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`NumConnection_u32` | `number` (uint32) | Number of connections
`ConnectionList` | `Array object` | Connection list
`Name_str` | `string` (ASCII) | Connection name
`Hostname_str` | `string` (ASCII) | Host name
`Ip_ip` | `string` (IP address) | IP address
`Port_u32` | `number` (uint32) | Port number
`ConnectedTime_dt` | `Date` | Connected time
`Type_u32` | `number` (enum) | Connection type<BR>Values:<BR>`0`: VPN Client<BR>`1`: During initialization<BR>`2`: Login connection<BR>`3`: Additional connection<BR>`4`: RPC for server farm<BR>`5`: RPC for Management<BR>`6`: HUB enumeration<BR>`7`: Password change<BR>`8`: SSTP<BR>`9`: OpenVPN

***
<a id="disconnectconnection"></a>
## "DisconnectConnection" RPC API - Disconnect TCP Connections Connecting to the VPN Server
### Description
Disconnect TCP Connections Connecting to the VPN Server. Use this to forcefully disconnect specific TCP/IP connections that are connecting to the VPN Server. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DisconnectConnection",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Connection name

***
<a id="getconnectioninfo"></a>
## "GetConnectionInfo" RPC API - Get Information of TCP Connections Connecting to the VPN Server
### Description
Get Information of TCP Connections Connecting to the VPN Server. Use this to get detailed information of a specific TCP/IP connection that is connecting to the VPN Server. You can get the following information: Connection Name, Connection Type, Source Hostname, Source IP Address, Source Port Number (TCP), Connection Start, Server Product Name, Server Version, Server Build Number, Client Product Name, Client Version, and Client Build Number. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetConnectionInfo",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "Type_u32": 0,
    "Hostname_str": "hostname",
    "Ip_ip": "192.168.0.1",
    "Port_u32": 0,
    "ConnectedTime_dt": "2020-08-01T12:24:36.123",
    "ServerStr_str": "serverstr",
    "ServerVer_u32": 0,
    "ServerBuild_u32": 0,
    "ClientStr_str": "clientstr",
    "ClientVer_u32": 0,
    "ClientBuild_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Connection name
`Type_u32` | `number` (enum) | Type<BR>Values:<BR>`0`: VPN Client<BR>`1`: During initialization<BR>`2`: Login connection<BR>`3`: Additional connection<BR>`4`: RPC for server farm<BR>`5`: RPC for Management<BR>`6`: HUB enumeration<BR>`7`: Password change<BR>`8`: SSTP<BR>`9`: OpenVPN
`Hostname_str` | `string` (ASCII) | Host name
`Ip_ip` | `string` (IP address) | IP address
`Port_u32` | `number` (uint32) | Port number
`ConnectedTime_dt` | `Date` | Connected time
`ServerStr_str` | `string` (ASCII) | Server string
`ServerVer_u32` | `number` (uint32) | Server version
`ServerBuild_u32` | `number` (uint32) | Server build number
`ClientStr_str` | `string` (ASCII) | Client string
`ClientVer_u32` | `number` (uint32) | Client version
`ClientBuild_u32` | `number` (uint32) | Client build number

***
<a id="sethubonline"></a>
## "SetHubOnline" RPC API - Switch Virtual Hub to Online or Offline
### Description
Switch Virtual Hub to Online or Offline. Use this to set the Virtual Hub to online or offline. A Virtual Hub with an offline status cannot receive VPN connections from clients. When you set the Virtual Hub offline, all sessions will be disconnected. A Virtual Hub with an offline status cannot receive VPN connections from clients. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubOnline",
  "params": {
    "HubName_str": "hubname",
    "Online_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Online_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online / offline flag

***
<a id="gethubstatus"></a>
## "GetHubStatus" RPC API - Get Current Status of Virtual Hub
### Description
Get Current Status of Virtual Hub. Use this to get the current status of the Virtual Hub currently being managed. You can get the following information: Virtual Hub Type, Number of Sessions, Number of Each Type of Object, Number of Logins, Last Login, Last Communication, and Communication Statistical Data.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubStatus",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Online_bool": false,
    "HubType_u32": 0,
    "NumSessions_u32": 0,
    "NumSessionsClient_u32": 0,
    "NumSessionsBridge_u32": 0,
    "NumAccessLists_u32": 0,
    "NumUsers_u32": 0,
    "NumGroups_u32": 0,
    "NumMacTables_u32": 0,
    "NumIpTables_u32": 0,
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "SecureNATEnabled_bool": false,
    "LastCommTime_dt": "2020-08-01T12:24:36.123",
    "LastLoginTime_dt": "2020-08-01T12:24:36.123",
    "CreatedTime_dt": "2020-08-01T12:24:36.123",
    "NumLogin_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online
`HubType_u32` | `number` (enum) | Type of HUB<BR>Values:<BR>`0`: Stand-alone HUB<BR>`1`: Static HUB<BR>`2`: Dynamic HUB
`NumSessions_u32` | `number` (uint32) | Number of sessions
`NumSessionsClient_u32` | `number` (uint32) | Number of sessions (client mode)
`NumSessionsBridge_u32` | `number` (uint32) | Number of sessions (bridge mode)
`NumAccessLists_u32` | `number` (uint32) | Number of Access list entries
`NumUsers_u32` | `number` (uint32) | Number of users
`NumGroups_u32` | `number` (uint32) | Number of groups
`NumMacTables_u32` | `number` (uint32) | Number of MAC table entries
`NumIpTables_u32` | `number` (uint32) | Number of IP table entries
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`SecureNATEnabled_bool` | `boolean` | Whether SecureNAT is enabled
`LastCommTime_dt` | `Date` | Last communication date and time
`LastLoginTime_dt` | `Date` | Last login date and time
`CreatedTime_dt` | `Date` | Creation date and time
`NumLogin_u32` | `number` (uint32) | Number of logins

***
<a id="sethublog"></a>
## "SetHubLog" RPC API - Set the logging configuration of the Virtual Hub
### Description
Set the logging configuration of the Virtual Hub. Use this to enable or disable a security log or packet logs of the Virtual Hub currently being managed, set the save contents of the packet log for each type of packet to be saved, and set the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. There are the following packet types: TCP Connection Log, TCP Packet Log, DHCP Packet Log, UDP Packet Log, ICMP Packet Log, IP Packet Log, ARP Packet Log, and Ethernet Packet Log. To get the current setting, you can use the LogGet API. The log file switch cycle can be changed to switch in every second, every minute, every hour, every day, every month or not switch. To get the current setting, you can use the GetHubLog API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubLog",
  "params": {
    "HubName_str": "hubname",
    "SaveSecurityLog_bool": false,
    "SecurityLogSwitchType_u32": 0,
    "SavePacketLog_bool": false,
    "PacketLogSwitchType_u32": 0,
    "PacketLogConfig_u32": [
      1,
      2,
      3
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "SaveSecurityLog_bool": false,
    "SecurityLogSwitchType_u32": 0,
    "SavePacketLog_bool": false,
    "PacketLogSwitchType_u32": 0,
    "PacketLogConfig_u32": [
      1,
      2,
      3
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`SaveSecurityLog_bool` | `boolean` | The flag to enable / disable saving the security log
`SecurityLogSwitchType_u32` | `number` (enum) | The log filename switching setting of the security log<BR>Values:<BR>`0`: No switching<BR>`1`: Secondly basis<BR>`2`: Minutely basis<BR>`3`: Hourly basis<BR>`4`: Daily basis<BR>`5`: Monthly basis
`SavePacketLog_bool` | `boolean` | The flag to enable / disable saving the security log
`PacketLogSwitchType_u32` | `number` (enum) | The log filename switching settings of the packet logs<BR>Values:<BR>`0`: No switching<BR>`1`: Secondly basis<BR>`2`: Minutely basis<BR>`3`: Hourly basis<BR>`4`: Daily basis<BR>`5`: Monthly basis
`PacketLogConfig_u32` | `number` (enum) | Specify the save contents of the packet logs (uint * 16 array). The index numbers: TcpConnection = 0, TcpAll = 1, DHCP = 2, UDP = 3, ICMP = 4, IP = 5, ARP = 6, Ethernet = 7.<BR>Values:<BR>`0`: Not save<BR>`1`: Only header<BR>`2`: All payloads

***
<a id="gethublog"></a>
## "GetHubLog" RPC API - Get the logging configuration of the Virtual Hub
### Description
Get the logging configuration of the Virtual Hub. Use this to get the configuration for a security log or packet logs of the Virtual Hub currently being managed, get the setting for save contents of the packet log for each type of packet to be saved, and get the log file switch cycle for the security log or packet log that the currently managed Virtual Hub saves. To set the current setting, you can use the SetHubLog API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubLog",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "SaveSecurityLog_bool": false,
    "SecurityLogSwitchType_u32": 0,
    "SavePacketLog_bool": false,
    "PacketLogSwitchType_u32": 0,
    "PacketLogConfig_u32": [
      1,
      2,
      3
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`SaveSecurityLog_bool` | `boolean` | The flag to enable / disable saving the security log
`SecurityLogSwitchType_u32` | `number` (enum) | The log filename switching setting of the security log<BR>Values:<BR>`0`: No switching<BR>`1`: Secondly basis<BR>`2`: Minutely basis<BR>`3`: Hourly basis<BR>`4`: Daily basis<BR>`5`: Monthly basis
`SavePacketLog_bool` | `boolean` | The flag to enable / disable saving the security log
`PacketLogSwitchType_u32` | `number` (enum) | The log filename switching settings of the packet logs<BR>Values:<BR>`0`: No switching<BR>`1`: Secondly basis<BR>`2`: Minutely basis<BR>`3`: Hourly basis<BR>`4`: Daily basis<BR>`5`: Monthly basis
`PacketLogConfig_u32` | `number` (enum) | Specify the save contents of the packet logs (uint * 16 array). The index numbers: TcpConnection = 0, TcpAll = 1, DHCP = 2, UDP = 3, ICMP = 4, IP = 5, ARP = 6, Ethernet = 7.<BR>Values:<BR>`0`: Not save<BR>`1`: Only header<BR>`2`: All payloads

***
<a id="addca"></a>
## "AddCa" RPC API - Add Trusted CA Certificate
### Description
Add Trusted CA Certificate. Use this to add a new certificate to a list of CA certificates trusted by the currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. To get a list of the current certificates you can use the EnumCa API. The certificate you add must be saved in the X.509 file format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddCa",
  "params": {
    "HubName_str": "hubname",
    "Cert_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Cert_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Cert_bin` | `string` (Base64 binary) | The body of the X.509 certificate

***
<a id="enumca"></a>
## "EnumCa" RPC API - Get List of Trusted CA Certificates
### Description
Get List of Trusted CA Certificates. Here you can manage the certificate authority certificates that are trusted by this currently managed Virtual Hub. The list of certificate authority certificates that are registered is used to verify certificates when a VPN Client is connected in signed certificate authentication mode. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumCa",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "CAList": [
      {
        "Key_u32": 0,
        "SubjectName_utf": "subjectname",
        "IssuerName_utf": "issuername",
        "Expires_dt": "2020-08-01T12:24:36.123"
      },
      {
        "Key_u32": 0,
        "SubjectName_utf": "subjectname",
        "IssuerName_utf": "issuername",
        "Expires_dt": "2020-08-01T12:24:36.123"
      },
      {
        "Key_u32": 0,
        "SubjectName_utf": "subjectname",
        "IssuerName_utf": "issuername",
        "Expires_dt": "2020-08-01T12:24:36.123"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`CAList` | `Array object` | The list of CA
`Key_u32` | `number` (uint32) | The key id of the item
`SubjectName_utf` | `string` (UTF8) | Subject
`IssuerName_utf` | `string` (UTF8) | Issuer
`Expires_dt` | `Date` | Expiration date

***
<a id="getca"></a>
## "GetCa" RPC API - Get Trusted CA Certificate
### Description
Get Trusted CA Certificate. Use this to get an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub and save it as a file in X.509 format. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetCa",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0,
    "Cert_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | The key id of the certificate
`Cert_bin` | `string` (Base64 binary) | The body of the X.509 certificate

***
<a id="deleteca"></a>
## "DeleteCa" RPC API - Delete Trusted CA Certificate
### Description
Delete Trusted CA Certificate. Use this to delete an existing certificate from the list of CA certificates trusted by the currently managed Virtual Hub. To get a list of the current certificates you can use the EnumCa API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteCa",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Certificate key id to be deleted

***
<a id="createlink"></a>
## "CreateLink" RPC API - Create New Cascade Connection
### Description
Create New Cascade Connection. Use this to create a new Cascade Connection on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Cascade Connection to another Virtual Hub that is operating on the same or a different computer. To create a Cascade Connection, you must specify the name of the Cascade Connection, destination server and destination Virtual Hub and user name. When a new Cascade Connection is created, the type of user authentication is initially set as Anonymous Authentication and the proxy server setting and the verification options of the server certificate is not set. To change these settings and other advanced settings after a Cascade Connection has been created, use the other APIs that include the name "Link". [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "CreateLink",
  "params": {
    "HubName_Ex_str": "hubname_ex",
    "CheckServerCert_bool": false,
    "AccountName_utf": "clientoption_accountname",
    "Hostname_str": "clientoption_hostname",
    "Port_u32": 0,
    "ProxyType_u32": 0,
    "HubName_str": "clientoption_hubname",
    "MaxConnection_u32": 0,
    "UseEncrypt_bool": false,
    "UseCompress_bool": false,
    "HalfConnection_bool": false,
    "AdditionalConnectionInterval_u32": 0,
    "ConnectionDisconnectSpan_u32": 0,
    "AuthType_u32": 0,
    "Username_str": "clientauth_username",
    "HashedPassword_bin": "SGVsbG8gV29ybGQ=",
    "PlainPassword_str": "clientauth_plainpassword",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "ClientK_bin": "SGVsbG8gV29ybGQ=",
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "SecPol_CheckMac_bool": false,
    "SecPol_CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:RSandRAFilter_bool": false,
    "SecPol_RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "SecPol_CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_Ex_str": "hubname_ex",
    "Online_bool": false,
    "CheckServerCert_bool": false,
    "ServerCert_bin": "SGVsbG8gV29ybGQ=",
    "AccountName_utf": "clientoption_accountname",
    "Hostname_str": "clientoption_hostname",
    "Port_u32": 0,
    "ProxyType_u32": 0,
    "ProxyName_str": "clientoption_proxyname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "clientoption_proxyusername",
    "ProxyPassword_str": "clientoption_proxypassword",
    "HubName_str": "clientoption_hubname",
    "MaxConnection_u32": 0,
    "UseEncrypt_bool": false,
    "UseCompress_bool": false,
    "HalfConnection_bool": false,
    "AdditionalConnectionInterval_u32": 0,
    "ConnectionDisconnectSpan_u32": 0,
    "DisableQoS_bool": false,
    "NoTls1_bool": false,
    "NoUdpAcceleration_bool": false,
    "AuthType_u32": 0,
    "Username_str": "clientauth_username",
    "HashedPassword_bin": "SGVsbG8gV29ybGQ=",
    "PlainPassword_str": "clientauth_plainpassword",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "ClientK_bin": "SGVsbG8gV29ybGQ=",
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "SecPol_CheckMac_bool": false,
    "SecPol_CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:RSandRAFilter_bool": false,
    "SecPol_RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "SecPol_CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_Ex_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`CheckServerCert_bool` | `boolean` | The flag to enable validation for the server certificate
`ServerCert_bin` | `string` (Base64 binary) | The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true.
`AccountName_utf` | `string` (UTF8) | Client Option Parameters: Specify the name of the Cascade Connection
`Hostname_str` | `string` (ASCII) | Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address.
`Port_u32` | `number` (uint32) | Client Option Parameters: Specify the port number of the destination VPN Server.
`ProxyType_u32` | `number` (enum) | Client Option Parameters: The type of the proxy server<BR>Values:<BR>`0`: Direct TCP connection<BR>`1`: Connection via HTTP proxy server<BR>`2`: Connection via SOCKS proxy server
`ProxyName_str` | `string` (ASCII) | Client Option Parameters: The hostname or IP address of the proxy server name
`ProxyPort_u32` | `number` (uint32) | Client Option Parameters: The port number of the proxy server
`ProxyUsername_str` | `string` (ASCII) | Client Option Parameters: The username to connect to the proxy server
`ProxyPassword_str` | `string` (ASCII) | Client Option Parameters: The password to connect to the proxy server
`HubName_str` | `string` (ASCII) | Client Option Parameters: The Virtual Hub on the destination VPN Server
`MaxConnection_u32` | `number` (uint32) | Client Option Parameters: Number of TCP Connections to Use in VPN Communication
`UseEncrypt_bool` | `boolean` | Client Option Parameters: The flag to enable the encryption on the communication
`UseCompress_bool` | `boolean` | Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection
`HalfConnection_bool` | `boolean` | Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction.
`AdditionalConnectionInterval_u32` | `number` (uint32) | Client Option Parameters: Connection attempt interval when additional connection will be established
`ConnectionDisconnectSpan_u32` | `number` (uint32) | Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive)
`DisableQoS_bool` | `boolean` | Client Option Parameters: Disable QoS Control Function if the value is true
`NoTls1_bool` | `boolean` | Client Option Parameters: Do not use TLS 1.x of the value is true
`NoUdpAcceleration_bool` | `boolean` | Client Option Parameters: Do not use UDP acceleration mode if the value is true
`AuthType_u32` | `number` (enum) | Authentication type<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: SHA-0 hashed password authentication<BR>`2`: Plain password authentication<BR>`3`: Certificate authentication
`Username_str` | `string` (ASCII) | User name
`HashedPassword_bin` | `string` (Base64 binary) | SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(password_ascii_string + UpperCase(username_ascii_string)).
`PlainPassword_str` | `string` (ASCII) | Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2).
`ClientX_bin` | `string` (Base64 binary) | Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`ClientK_bin` | `string` (Base64 binary) | Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`SecPol_CheckMac_bool` | `boolean` | Security policy: Prohibit the duplicate MAC address
`SecPol_CheckIP_bool` | `boolean` | Security policy: Prohibit a duplicate IP address (IPv4)
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`SecPol_RAFilter_bool` | `boolean` | Security policy: Filter the router advertisement packet (IPv6)
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`SecPol_CheckIPv6_bool` | `boolean` | Security policy: Prohibit the duplicate IP address (IPv6)
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="getlink"></a>
## "GetLink" RPC API - Get the Cascade Connection Setting
### Description
Get the Cascade Connection Setting. Use this to get the Connection Setting of a Cascade Connection that is registered on the currently managed Virtual Hub. To change the Connection Setting contents of the Cascade Connection, use the APIs that include the name "Link" after creating the Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetLink",
  "params": {
    "HubName_Ex_str": "hubname_ex",
    "AccountName_utf": "clientoption_accountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_Ex_str": "hubname_ex",
    "Online_bool": false,
    "CheckServerCert_bool": false,
    "ServerCert_bin": "SGVsbG8gV29ybGQ=",
    "AccountName_utf": "clientoption_accountname",
    "Hostname_str": "clientoption_hostname",
    "Port_u32": 0,
    "ProxyType_u32": 0,
    "ProxyName_str": "clientoption_proxyname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "clientoption_proxyusername",
    "ProxyPassword_str": "clientoption_proxypassword",
    "HubName_str": "clientoption_hubname",
    "MaxConnection_u32": 0,
    "UseEncrypt_bool": false,
    "UseCompress_bool": false,
    "HalfConnection_bool": false,
    "AdditionalConnectionInterval_u32": 0,
    "ConnectionDisconnectSpan_u32": 0,
    "DisableQoS_bool": false,
    "NoTls1_bool": false,
    "NoUdpAcceleration_bool": false,
    "AuthType_u32": 0,
    "Username_str": "clientauth_username",
    "HashedPassword_bin": "SGVsbG8gV29ybGQ=",
    "PlainPassword_str": "clientauth_plainpassword",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "ClientK_bin": "SGVsbG8gV29ybGQ=",
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "SecPol_CheckMac_bool": false,
    "SecPol_CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:RSandRAFilter_bool": false,
    "SecPol_RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "SecPol_CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_Ex_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`CheckServerCert_bool` | `boolean` | The flag to enable validation for the server certificate
`ServerCert_bin` | `string` (Base64 binary) | The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true.
`AccountName_utf` | `string` (UTF8) | Client Option Parameters: Specify the name of the Cascade Connection
`Hostname_str` | `string` (ASCII) | Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address.
`Port_u32` | `number` (uint32) | Client Option Parameters: Specify the port number of the destination VPN Server.
`ProxyType_u32` | `number` (enum) | Client Option Parameters: The type of the proxy server<BR>Values:<BR>`0`: Direct TCP connection<BR>`1`: Connection via HTTP proxy server<BR>`2`: Connection via SOCKS proxy server
`ProxyName_str` | `string` (ASCII) | Client Option Parameters: The hostname or IP address of the proxy server name
`ProxyPort_u32` | `number` (uint32) | Client Option Parameters: The port number of the proxy server
`ProxyUsername_str` | `string` (ASCII) | Client Option Parameters: The username to connect to the proxy server
`ProxyPassword_str` | `string` (ASCII) | Client Option Parameters: The password to connect to the proxy server
`HubName_str` | `string` (ASCII) | Client Option Parameters: The Virtual Hub on the destination VPN Server
`MaxConnection_u32` | `number` (uint32) | Client Option Parameters: Number of TCP Connections to Use in VPN Communication
`UseEncrypt_bool` | `boolean` | Client Option Parameters: The flag to enable the encryption on the communication
`UseCompress_bool` | `boolean` | Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection
`HalfConnection_bool` | `boolean` | Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction.
`AdditionalConnectionInterval_u32` | `number` (uint32) | Client Option Parameters: Connection attempt interval when additional connection will be established
`ConnectionDisconnectSpan_u32` | `number` (uint32) | Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive)
`DisableQoS_bool` | `boolean` | Client Option Parameters: Disable QoS Control Function if the value is true
`NoTls1_bool` | `boolean` | Client Option Parameters: Do not use TLS 1.x of the value is true
`NoUdpAcceleration_bool` | `boolean` | Client Option Parameters: Do not use UDP acceleration mode if the value is true
`AuthType_u32` | `number` (enum) | Authentication type<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: SHA-0 hashed password authentication<BR>`2`: Plain password authentication<BR>`3`: Certificate authentication
`Username_str` | `string` (ASCII) | User name
`HashedPassword_bin` | `string` (Base64 binary) | SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(password_ascii_string + UpperCase(username_ascii_string)).
`PlainPassword_str` | `string` (ASCII) | Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2).
`ClientX_bin` | `string` (Base64 binary) | Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`ClientK_bin` | `string` (Base64 binary) | Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`SecPol_CheckMac_bool` | `boolean` | Security policy: Prohibit the duplicate MAC address
`SecPol_CheckIP_bool` | `boolean` | Security policy: Prohibit a duplicate IP address (IPv4)
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`SecPol_RAFilter_bool` | `boolean` | Security policy: Filter the router advertisement packet (IPv6)
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`SecPol_CheckIPv6_bool` | `boolean` | Security policy: Prohibit the duplicate IP address (IPv6)
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="setlink"></a>
## "SetLink" RPC API - Change Existing Cascade Connection
### Description
Change Existing Cascade Connection. Use this to alter the setting of an existing Cascade Connection on the currently managed Virtual Hub.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetLink",
  "params": {
    "HubName_Ex_str": "hubname_ex",
    "CheckServerCert_bool": false,
    "AccountName_utf": "clientoption_accountname",
    "Hostname_str": "clientoption_hostname",
    "Port_u32": 0,
    "ProxyType_u32": 0,
    "HubName_str": "clientoption_hubname",
    "MaxConnection_u32": 0,
    "UseEncrypt_bool": false,
    "UseCompress_bool": false,
    "HalfConnection_bool": false,
    "AdditionalConnectionInterval_u32": 0,
    "ConnectionDisconnectSpan_u32": 0,
    "AuthType_u32": 0,
    "Username_str": "clientauth_username",
    "HashedPassword_bin": "SGVsbG8gV29ybGQ=",
    "PlainPassword_str": "clientauth_plainpassword",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "ClientK_bin": "SGVsbG8gV29ybGQ=",
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "SecPol_CheckMac_bool": false,
    "SecPol_CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:RSandRAFilter_bool": false,
    "SecPol_RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "SecPol_CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_Ex_str": "hubname_ex",
    "Online_bool": false,
    "CheckServerCert_bool": false,
    "ServerCert_bin": "SGVsbG8gV29ybGQ=",
    "AccountName_utf": "clientoption_accountname",
    "Hostname_str": "clientoption_hostname",
    "Port_u32": 0,
    "ProxyType_u32": 0,
    "ProxyName_str": "clientoption_proxyname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "clientoption_proxyusername",
    "ProxyPassword_str": "clientoption_proxypassword",
    "HubName_str": "clientoption_hubname",
    "MaxConnection_u32": 0,
    "UseEncrypt_bool": false,
    "UseCompress_bool": false,
    "HalfConnection_bool": false,
    "AdditionalConnectionInterval_u32": 0,
    "ConnectionDisconnectSpan_u32": 0,
    "DisableQoS_bool": false,
    "NoTls1_bool": false,
    "NoUdpAcceleration_bool": false,
    "AuthType_u32": 0,
    "Username_str": "clientauth_username",
    "HashedPassword_bin": "SGVsbG8gV29ybGQ=",
    "PlainPassword_str": "clientauth_plainpassword",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "ClientK_bin": "SGVsbG8gV29ybGQ=",
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "SecPol_CheckMac_bool": false,
    "SecPol_CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:RSandRAFilter_bool": false,
    "SecPol_RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "SecPol_CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_Ex_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`CheckServerCert_bool` | `boolean` | The flag to enable validation for the server certificate
`ServerCert_bin` | `string` (Base64 binary) | The body of server X.509 certificate to compare. Valid only if the CheckServerCert_bool flag is true.
`AccountName_utf` | `string` (UTF8) | Client Option Parameters: Specify the name of the Cascade Connection
`Hostname_str` | `string` (ASCII) | Client Option Parameters: Specify the hostname of the destination VPN Server. You can also specify by IP address.
`Port_u32` | `number` (uint32) | Client Option Parameters: Specify the port number of the destination VPN Server.
`ProxyType_u32` | `number` (enum) | Client Option Parameters: The type of the proxy server<BR>Values:<BR>`0`: Direct TCP connection<BR>`1`: Connection via HTTP proxy server<BR>`2`: Connection via SOCKS proxy server
`ProxyName_str` | `string` (ASCII) | Client Option Parameters: The hostname or IP address of the proxy server name
`ProxyPort_u32` | `number` (uint32) | Client Option Parameters: The port number of the proxy server
`ProxyUsername_str` | `string` (ASCII) | Client Option Parameters: The username to connect to the proxy server
`ProxyPassword_str` | `string` (ASCII) | Client Option Parameters: The password to connect to the proxy server
`HubName_str` | `string` (ASCII) | Client Option Parameters: The Virtual Hub on the destination VPN Server
`MaxConnection_u32` | `number` (uint32) | Client Option Parameters: Number of TCP Connections to Use in VPN Communication
`UseEncrypt_bool` | `boolean` | Client Option Parameters: The flag to enable the encryption on the communication
`UseCompress_bool` | `boolean` | Client Option Parameters: Enable / Disable Data Compression when Communicating by Cascade Connection
`HalfConnection_bool` | `boolean` | Client Option Parameters: Specify true when enabling half duplex mode. When using two or more TCP connections for VPN communication, it is possible to use Half Duplex Mode. By enabling half duplex mode it is possible to automatically fix data transmission direction as half and half for each TCP connection. In the case where a VPN using 8 TCP connections is established, for example, when half-duplex is enabled, communication can be fixes so that 4 TCP connections are dedicated to the upload direction and the other 4 connections are dedicated to the download direction.
`AdditionalConnectionInterval_u32` | `number` (uint32) | Client Option Parameters: Connection attempt interval when additional connection will be established
`ConnectionDisconnectSpan_u32` | `number` (uint32) | Client Option Parameters: Connection Life of Each TCP Connection (0 for no keep-alive)
`DisableQoS_bool` | `boolean` | Client Option Parameters: Disable QoS Control Function if the value is true
`NoTls1_bool` | `boolean` | Client Option Parameters: Do not use TLS 1.x of the value is true
`NoUdpAcceleration_bool` | `boolean` | Client Option Parameters: Do not use UDP acceleration mode if the value is true
`AuthType_u32` | `number` (enum) | Authentication type<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: SHA-0 hashed password authentication<BR>`2`: Plain password authentication<BR>`3`: Certificate authentication
`Username_str` | `string` (ASCII) | User name
`HashedPassword_bin` | `string` (Base64 binary) | SHA-0 Hashed password. Valid only if ClientAuth_AuthType_u32 == SHA0_Hashed_Password (1). The SHA-0 hashed password must be caluclated by the SHA0(password_ascii_string + UpperCase(username_ascii_string)).
`PlainPassword_str` | `string` (ASCII) | Plaintext Password. Valid only if ClientAuth_AuthType_u32 == PlainPassword (2).
`ClientX_bin` | `string` (Base64 binary) | Client certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`ClientK_bin` | `string` (Base64 binary) | Client private key of the certificate. Valid only if ClientAuth_AuthType_u32 == Cert (3).
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`SecPol_CheckMac_bool` | `boolean` | Security policy: Prohibit the duplicate MAC address
`SecPol_CheckIP_bool` | `boolean` | Security policy: Prohibit a duplicate IP address (IPv4)
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`SecPol_RAFilter_bool` | `boolean` | Security policy: Filter the router advertisement packet (IPv6)
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`SecPol_CheckIPv6_bool` | `boolean` | Security policy: Prohibit the duplicate IP address (IPv6)
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="enumlink"></a>
## "EnumLink" RPC API - Get List of Cascade Connections
### Description
Get List of Cascade Connections. Use this to get a list of Cascade Connections that are registered on the currently managed Virtual Hub. By using a Cascade Connection, you can connect this Virtual Hub by Layer 2 Cascade Connection to another Virtual Hub that is operating on the same or a different computer. [Warning About Cascade Connections] By connecting using a Cascade Connection you can create a Layer 2 bridge between multiple Virtual Hubs but if the connection is incorrectly configured, a loopback Cascade Connection could inadvertently be created. When using a Cascade Connection function please design the network topology with care. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumLink",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "NumLink_u32": 0,
    "LinkList": [
      {
        "AccountName_utf": "accountname",
        "Online_bool": false,
        "Connected_bool": false,
        "LastError_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Hostname_str": "hostname",
        "TargetHubName_str": "targethubname"
      },
      {
        "AccountName_utf": "accountname",
        "Online_bool": false,
        "Connected_bool": false,
        "LastError_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Hostname_str": "hostname",
        "TargetHubName_str": "targethubname"
      },
      {
        "AccountName_utf": "accountname",
        "Online_bool": false,
        "Connected_bool": false,
        "LastError_u32": 0,
        "ConnectedTime_dt": "2020-08-01T12:24:36.123",
        "Hostname_str": "hostname",
        "TargetHubName_str": "targethubname"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`NumLink_u32` | `number` (uint32) | Number of cascade connections
`LinkList` | `Array object` | The list of cascade connections
`AccountName_utf` | `string` (UTF8) | The name of cascade connection
`Online_bool` | `boolean` | Online flag
`Connected_bool` | `boolean` | The flag indicates whether the cascade connection is established
`LastError_u32` | `number` (uint32) | The error last occurred if the cascade connection is in the fail state
`ConnectedTime_dt` | `Date` | Connection completion time
`Hostname_str` | `string` (ASCII) | Host name of the destination VPN server
`TargetHubName_str` | `string` (ASCII) | The Virtual Hub name

***
<a id="setlinkonline"></a>
## "SetLinkOnline" RPC API - Switch Cascade Connection to Online Status
### Description
Switch Cascade Connection to Online Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to online status. The Cascade Connection that is switched to online status begins the process of connecting to the destination VPN Server in accordance with the Connection Setting. The Cascade Connection that is switched to online status will establish normal connection to the VPN Server or continue to attempt connection until it is switched to offline status. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetLinkOnline",
  "params": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccountName_utf` | `string` (UTF8) | The name of the cascade connection

***
<a id="setlinkoffline"></a>
## "SetLinkOffline" RPC API - Switch Cascade Connection to Offline Status
### Description
Switch Cascade Connection to Offline Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to switch that Cascade Connection to offline status. The Cascade Connection that is switched to offline will not connect to the VPN Server until next time it is switched to the online status using the SetLinkOnline API You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetLinkOffline",
  "params": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccountName_utf` | `string` (UTF8) | The name of the cascade connection

***
<a id="deletelink"></a>
## "DeleteLink" RPC API - Delete Cascade Connection Setting
### Description
Delete Cascade Connection Setting. Use this to delete a Cascade Connection that is registered on the currently managed Virtual Hub. If the specified Cascade Connection has a status of online, the connections will be automatically disconnected and then the Cascade Connection will be deleted. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteLink",
  "params": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccountName_utf": "accountname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccountName_utf` | `string` (UTF8) | The name of the cascade connection

***
<a id="renamelink"></a>
## "RenameLink" RPC API - Change Name of Cascade Connection
### Description
Change Name of Cascade Connection. When a Cascade Connection registered on the currently managed Virtual Hub is specified, use this to change the name of that Cascade Connection. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "RenameLink",
  "params": {
    "HubName_str": "hubname",
    "OldAccountName_utf": "oldaccountname",
    "NewAccountName_utf": "newaccountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "OldAccountName_utf": "oldaccountname",
    "NewAccountName_utf": "newaccountname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`OldAccountName_utf` | `string` (UTF8) | The old name of the cascade connection
`NewAccountName_utf` | `string` (UTF8) | The new name of the cascade connection

***
<a id="getlinkstatus"></a>
## "GetLinkStatus" RPC API - Get Current Cascade Connection Status
### Description
Get Current Cascade Connection Status. When a Cascade Connection registered on the currently managed Virtual Hub is specified and that Cascade Connection is currently online, use this to get its connection status and other information. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetLinkStatus",
  "params": {
    "HubName_Ex_str": "hubname_ex",
    "AccountName_utf": "accountname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_Ex_str": "hubname_ex",
    "AccountName_utf": "accountname",
    "Active_bool": false,
    "Connected_bool": false,
    "SessionStatus_u32": 0,
    "ServerName_str": "servername",
    "ServerPort_u32": 0,
    "ServerProductName_str": "serverproductname",
    "ServerProductVer_u32": 0,
    "ServerProductBuild_u32": 0,
    "ServerX_bin": "SGVsbG8gV29ybGQ=",
    "ClientX_bin": "SGVsbG8gV29ybGQ=",
    "StartTime_dt": "2020-08-01T12:24:36.123",
    "FirstConnectionEstablisiedTime_dt": "2020-08-01T12:24:36.123",
    "CurrentConnectionEstablishTime_dt": "2020-08-01T12:24:36.123",
    "NumConnectionsEatablished_u32": 0,
    "HalfConnection_bool": false,
    "QoS_bool": false,
    "MaxTcpConnections_u32": 0,
    "NumTcpConnections_u32": 0,
    "NumTcpConnectionsUpload_u32": 0,
    "NumTcpConnectionsDownload_u32": 0,
    "UseEncrypt_bool": false,
    "CipherName_str": "ciphername",
    "UseCompress_bool": false,
    "IsRUDPSession_bool": false,
    "UnderlayProtocol_str": "underlayprotocol",
    "IsUdpAccelerationEnabled_bool": false,
    "IsUsingUdpAcceleration_bool": false,
    "SessionName_str": "sessionname",
    "ConnectionName_str": "connectionname",
    "SessionKey_bin": "SGVsbG8gV29ybGQ=",
    "TotalSendSize_u64": 0,
    "TotalRecvSize_u64": 0,
    "TotalSendSizeReal_u64": 0,
    "TotalRecvSizeReal_u64": 0,
    "IsBridgeMode_bool": false,
    "IsMonitorMode_bool": false,
    "VLanId_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_Ex_str` | `string` (ASCII) | The Virtual Hub name
`AccountName_utf` | `string` (UTF8) | The name of the cascade connection
`Active_bool` | `boolean` | The flag whether the cascade connection is enabled
`Connected_bool` | `boolean` | The flag whether the cascade connection is established
`SessionStatus_u32` | `number` (enum) | The session status<BR>Values:<BR>`0`: Connecting<BR>`1`: Negotiating<BR>`2`: During user authentication<BR>`3`: Connection complete<BR>`4`: Wait to retry<BR>`5`: Idle state
`ServerName_str` | `string` (ASCII) | The destination VPN server name
`ServerPort_u32` | `number` (uint32) | The port number of the server
`ServerProductName_str` | `string` (ASCII) | Server product name
`ServerProductVer_u32` | `number` (uint32) | Server product version
`ServerProductBuild_u32` | `number` (uint32) | Server product build number
`ServerX_bin` | `string` (Base64 binary) | Server's X.509 certificate
`ClientX_bin` | `string` (Base64 binary) | Client certificate
`StartTime_dt` | `Date` | Connection start time
`FirstConnectionEstablisiedTime_dt` | `Date` | Connection completion time of the first connection
`CurrentConnectionEstablishTime_dt` | `Date` | Connection completion time of this connection
`NumConnectionsEatablished_u32` | `number` (uint32) | Number of connections have been established so far
`HalfConnection_bool` | `boolean` | Half-connection
`QoS_bool` | `boolean` | VoIP / QoS
`MaxTcpConnections_u32` | `number` (uint32) | Maximum number of the underlying TCP connections
`NumTcpConnections_u32` | `number` (uint32) | Number of current underlying TCP connections
`NumTcpConnectionsUpload_u32` | `number` (uint32) | Number of underlying inbound TCP connections
`NumTcpConnectionsDownload_u32` | `number` (uint32) | Number of underlying outbound TCP connections
`UseEncrypt_bool` | `boolean` | Use of encryption
`CipherName_str` | `string` (ASCII) | Cipher algorithm name
`UseCompress_bool` | `boolean` | Use of compression
`IsRUDPSession_bool` | `boolean` | The flag whether this is a R-UDP session
`UnderlayProtocol_str` | `string` (ASCII) | Underlying physical communication protocol
`IsUdpAccelerationEnabled_bool` | `boolean` | The UDP acceleration is enabled
`IsUsingUdpAcceleration_bool` | `boolean` | The UDP acceleration is being actually used
`SessionName_str` | `string` (ASCII) | Session name
`ConnectionName_str` | `string` (ASCII) | Connection name
`SessionKey_bin` | `string` (Base64 binary) | Session key
`TotalSendSize_u64` | `number` (uint64) | Total transmitted data size
`TotalRecvSize_u64` | `number` (uint64) | Total received data size
`TotalSendSizeReal_u64` | `number` (uint64) | Total transmitted data size (no compression)
`TotalRecvSizeReal_u64` | `number` (uint64) | Total received data size (no compression)
`IsBridgeMode_bool` | `boolean` | The flag whether the VPN session is Bridge Mode
`IsMonitorMode_bool` | `boolean` | The flag whether the VPN session is Monitor mode
`VLanId_u32` | `number` (uint32) | VLAN ID

***
<a id="addaccess"></a>
## "AddAccess" RPC API - Add Access List Rule
### Description
Add Access List Rule. Use this to add a new rule to the access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define an priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. You can also use the access list to generate delays, jitters and packet losses. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddAccess",
  "params": {
    "HubName_str": "hubname",
    "AccessListSingle": [
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      }
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccessListSingle": [
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccessListSingle` | `Array object` | Access list (Must be a single item)
`Id_u32` | `number` (uint32) | ID
`Note_utf` | `string` (UTF8) | Specify a description (note) for this rule
`Active_bool` | `boolean` | Enabled flag (true: enabled, false: disabled)
`Priority_u32` | `number` (uint32) | Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values.
`Discard_bool` | `boolean` | The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded.
`IsIPv6_bool` | `boolean` | The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6.
`SrcIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field.
`SrcSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`DestIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field.
`DestSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`SrcIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field.
`SrcSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`DestIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field.
`DestSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`Protocol_u32` | `number` (enum) | The IP protocol number<BR>Values:<BR>`1`: ICMP for IPv4<BR>`6`: TCP<BR>`17`: UDP<BR>`58`: ICMP for IPv6
`SrcPortStart_u32` | `number` (uint32) | The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcPortEnd_u32` | `number` (uint32) | The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortStart_u32` | `number` (uint32) | The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortEnd_u32` | `number` (uint32) | The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcUsername_str` | `string` (ASCII) | Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`DestUsername_str` | `string` (ASCII) | Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`CheckSrcMac_bool` | `boolean` | Specify true if you want to check the source MAC address.
`SrcMacAddress_bin` | `string` (Base64 binary) | Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`SrcMacMask_bin` | `string` (Base64 binary) | Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckDstMac_bool` | `boolean` | Specify true if you want to check the destination MAC address.
`DstMacAddress_bin` | `string` (Base64 binary) | Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`DstMacMask_bin` | `string` (Base64 binary) | Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckTcpState_bool` | `boolean` | Specify true if you want to check the state of the TCP connection.
`Established_bool` | `boolean` | Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets.
`Delay_u32` | `number` (uint32) | Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most.
`Jitter_u32` | `number` (uint32) | Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate.
`Loss_u32` | `number` (uint32) | Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate.
`RedirectUrl_str` | `string` (ASCII) | The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address.

***
<a id="deleteaccess"></a>
## "DeleteAccess" RPC API - Delete Rule from Access List
### Description
Delete Rule from Access List. Use this to specify a packet filter rule registered on the access list of the currently managed Virtual Hub and delete it. To delete a rule, you must specify that rule's ID. You can display the ID by using the EnumAccess API. If you wish not to delete the rule but to only temporarily disable it, use the SetAccessList API to set the rule status to disable. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteAccess",
  "params": {
    "HubName_str": "hubname",
    "Id_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Id_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Id_u32` | `number` (uint32) | ID

***
<a id="enumaccess"></a>
## "EnumAccess" RPC API - Get Access List Rule List
### Description
Get Access List Rule List. Use this to get a list of packet filter rules that are registered on access list of the currently managed Virtual Hub. The access list is a set of packet file rules that are applied to packets that flow through the Virtual Hub. You can register multiple rules in an access list and you can also define a priority for each rule. All packets are checked for the conditions specified by the rules registered in the access list and based on the operation that is stipulated by the first matching rule, they either pass or are discarded. Packets that do not match any rule are implicitly allowed to pass. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumAccess",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccessList": [
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccessList` | `Array object` | Access list
`Id_u32` | `number` (uint32) | ID
`Note_utf` | `string` (UTF8) | Specify a description (note) for this rule
`Active_bool` | `boolean` | Enabled flag (true: enabled, false: disabled)
`Priority_u32` | `number` (uint32) | Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values.
`Discard_bool` | `boolean` | The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded.
`IsIPv6_bool` | `boolean` | The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6.
`SrcIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field.
`SrcSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`DestIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field.
`DestSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`SrcIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field.
`SrcSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`DestIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field.
`DestSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`Protocol_u32` | `number` (enum) | The IP protocol number<BR>Values:<BR>`1`: ICMP for IPv4<BR>`6`: TCP<BR>`17`: UDP<BR>`58`: ICMP for IPv6
`SrcPortStart_u32` | `number` (uint32) | The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcPortEnd_u32` | `number` (uint32) | The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortStart_u32` | `number` (uint32) | The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortEnd_u32` | `number` (uint32) | The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcUsername_str` | `string` (ASCII) | Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`DestUsername_str` | `string` (ASCII) | Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`CheckSrcMac_bool` | `boolean` | Specify true if you want to check the source MAC address.
`SrcMacAddress_bin` | `string` (Base64 binary) | Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`SrcMacMask_bin` | `string` (Base64 binary) | Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckDstMac_bool` | `boolean` | Specify true if you want to check the destination MAC address.
`DstMacAddress_bin` | `string` (Base64 binary) | Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`DstMacMask_bin` | `string` (Base64 binary) | Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckTcpState_bool` | `boolean` | Specify true if you want to check the state of the TCP connection.
`Established_bool` | `boolean` | Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets.
`Delay_u32` | `number` (uint32) | Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most.
`Jitter_u32` | `number` (uint32) | Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate.
`Loss_u32` | `number` (uint32) | Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate.
`RedirectUrl_str` | `string` (ASCII) | The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address.

***
<a id="setaccesslist"></a>
## "SetAccessList" RPC API - Replace all access lists on a single bulk API call
### Description
Replace all access lists on a single bulk API call. This API removes all existing access list rules on the Virtual Hub, and replace them by new access list rules specified by the parameter.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetAccessList",
  "params": {
    "HubName_str": "hubname",
    "AccessList": [
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      }
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AccessList": [
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      },
      {
        "Id_u32": 0,
        "Note_utf": "note",
        "Active_bool": false,
        "Priority_u32": 0,
        "Discard_bool": false,
        "IsIPv6_bool": false,
        "SrcIpAddress_ip": "192.168.0.1",
        "SrcSubnetMask_ip": "255.255.255.255",
        "DestIpAddress_ip": "192.168.0.1",
        "DestSubnetMask_ip": "255.255.255.255",
        "SrcIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "SrcSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "DestIpAddress6_bin": "SGVsbG8gV29ybGQ=",
        "DestSubnetMask6_bin": "SGVsbG8gV29ybGQ=",
        "Protocol_u32": 0,
        "SrcPortStart_u32": 0,
        "SrcPortEnd_u32": 0,
        "DestPortStart_u32": 0,
        "DestPortEnd_u32": 0,
        "SrcUsername_str": "srcusername",
        "DestUsername_str": "destusername",
        "CheckSrcMac_bool": false,
        "SrcMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "SrcMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckDstMac_bool": false,
        "DstMacAddress_bin": "SGVsbG8gV29ybGQ=",
        "DstMacMask_bin": "SGVsbG8gV29ybGQ=",
        "CheckTcpState_bool": false,
        "Established_bool": false,
        "Delay_u32": 0,
        "Jitter_u32": 0,
        "Loss_u32": 0,
        "RedirectUrl_str": "redirecturl"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`AccessList` | `Array object` | Access list
`Id_u32` | `number` (uint32) | ID
`Note_utf` | `string` (UTF8) | Specify a description (note) for this rule
`Active_bool` | `boolean` | Enabled flag (true: enabled, false: disabled)
`Priority_u32` | `number` (uint32) | Specify an integer of 1 or higher to indicate the priority of the rule. Higher priority is given to rules with the lower priority values.
`Discard_bool` | `boolean` | The flag if the rule is DISCARD operation or PASS operation. When a packet matches this rule condition, this operation is decided. When the operation of the rule is PASS, the packet is allowed to pass, otherwise the packet will be discarded.
`IsIPv6_bool` | `boolean` | The flag if the rule is for IPv6. Specify false for IPv4, or specify true for IPv6.
`SrcIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 address as a rule condition. You must also specify the SrcSubnetMask_ip field.
`SrcSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a source IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`DestIpAddress_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 address as a rule condition. You must also specify the DestSubnetMask_ip field.
`DestSubnetMask_ip` | `string` (IP address) | Valid only if the rule is IPv4 mode (IsIPv6_bool == false). Specify a destination IPv4 subnet mask as a rule condition. "0.0.0.0" means all hosts. "255.255.255.255" means one single host.
`SrcIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the SrcSubnetMask6_bin field.
`SrcSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a source IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`DestIpAddress6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 address as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 address in binary form. You must also specify the DestSubnetMask6_bin field.
`DestSubnetMask6_bin` | `string` (Base64 binary) | Valid only if the rule is IPv6 mode (IsIPv6_bool == true). Specify a destination IPv6 subnet mask as a rule condition. The field must be a byte array of 16 bytes (128 bits) to contain the IPv6 subnet mask in binary form.
`Protocol_u32` | `number` (enum) | The IP protocol number<BR>Values:<BR>`1`: ICMP for IPv4<BR>`6`: TCP<BR>`17`: UDP<BR>`58`: ICMP for IPv6
`SrcPortStart_u32` | `number` (uint32) | The Start Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcPortEnd_u32` | `number` (uint32) | The End Value of the Source Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the source port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortStart_u32` | `number` (uint32) | The Start Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`DestPortEnd_u32` | `number` (uint32) | The End Value of the Destination Port Number Range. If the specified protocol is TCP/IP or UDP/IP, specify the destination port number as the rule condition. Protocols other than this will be ignored. When this parameter is not specified, the rules will apply to all port numbers.
`SrcUsername_str` | `string` (ASCII) | Source user name. You can apply this rule to only the packets sent by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`DestUsername_str` | `string` (ASCII) | Destination user name. You can apply this rule to only the packets received by a user session of a user name that has been specified as a rule condition. In this case, specify the user name.
`CheckSrcMac_bool` | `boolean` | Specify true if you want to check the source MAC address.
`SrcMacAddress_bin` | `string` (Base64 binary) | Source MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`SrcMacMask_bin` | `string` (Base64 binary) | Source MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckDstMac_bool` | `boolean` | Specify true if you want to check the destination MAC address.
`DstMacAddress_bin` | `string` (Base64 binary) | Destination MAC address (6 bytes), valid only if CheckSrcMac_bool == true.
`DstMacMask_bin` | `string` (Base64 binary) | Destination MAC address mask (6 bytes), valid only if CheckSrcMac_bool == true.
`CheckTcpState_bool` | `boolean` | Specify true if you want to check the state of the TCP connection.
`Established_bool` | `boolean` | Valid only if CheckTcpState_bool == true. Set this field true to match only TCP-established packets. Set this field false to match only TCP-non established packets.
`Delay_u32` | `number` (uint32) | Set this value to generate delays when packets is passing. Specify the delay period in milliseconds. Specify 0 means no delays to generate. The delays must be 10000 milliseconds at most.
`Jitter_u32` | `number` (uint32) | Set this value to generate jitters when packets is passing. Specify the ratio of fluctuation of jitters within 0% to 100% range. Specify 0 means no jitters to generate.
`Loss_u32` | `number` (uint32) | Set this value to generate packet losses when packets is passing. Specify the ratio of packet losses within 0% to 100% range. Specify 0 means no packet losses to generate.
`RedirectUrl_str` | `string` (ASCII) | The specified URL will be mandatory replied to the client as a response for TCP connecting request packets which matches the conditions of this access list entry via this Virtual Hub. To use this setting, you can enforce the web browser of the VPN Client computer to show the specified web site when that web browser tries to access the specific IP address.

***
<a id="createuser"></a>
## "CreateUser" RPC API - Create a user
### Description
Create a user. Use this to create a new user in the security account database of the currently managed Virtual Hub. By creating a user, the VPN Client can connect to the Virtual Hub by using the authentication information of that user. Note that a user whose user name has been created as "*" (a single asterisk character) will automatically be registered as a RADIUS authentication user. For cases where there are users with "*" as the name, when a user, whose user name that has been provided when a client connected to a VPN Server does not match existing user names, is able to be authenticated by a RADIUS server or NT domain controller by inputting a user name and password, the authentication settings and security policy settings will follow the setting for the user "*". To change the user information of a user that has been created, use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "CreateUser",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "ExpireTime_dt": "2020-08-01T12:24:36.123",
    "AuthType_u32": 0,
    "Auth_Password_str": "auth_password",
    "UserX_bin": "SGVsbG8gV29ybGQ=",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "CommonName_utf": "auth_rootcert_commonname",
    "RadiusUsername_utf": "auth_radius_radiususername",
    "NtUsername_utf": "auth_nt_ntusername",
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "GroupName_str": "groupname",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "CreatedTime_dt": "2020-08-01T12:24:36.123",
    "UpdatedTime_dt": "2020-08-01T12:24:36.123",
    "ExpireTime_dt": "2020-08-01T12:24:36.123",
    "AuthType_u32": 0,
    "Auth_Password_str": "auth_password",
    "UserX_bin": "SGVsbG8gV29ybGQ=",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "CommonName_utf": "auth_rootcert_commonname",
    "RadiusUsername_utf": "auth_radius_radiususername",
    "NtUsername_utf": "auth_nt_ntusername",
    "NumLogin_u32": 0,
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | Specify the user name of the user
`GroupName_str` | `string` (ASCII) | Assigned group name for the user
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the user, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional User Description
`CreatedTime_dt` | `Date` | Creation date and time
`UpdatedTime_dt` | `Date` | Last modified date and time
`ExpireTime_dt` | `Date` | Expiration date and time
`AuthType_u32` | `number` (enum) | Authentication method of the user<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: Password authentication<BR>`2`: User certificate authentication<BR>`3`: Root certificate which is issued by trusted Certificate Authority<BR>`4`: Radius authentication<BR>`5`: Windows NT authentication
`Auth_Password_str` | `string` (ASCII) | User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations.
`UserX_bin` | `string` (Base64 binary) | User certificate, valid only if AuthType_u32 == UserCert(2).
`Serial_bin` | `string` (Base64 binary) | Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3).
`CommonName_utf` | `string` (UTF8) | Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3).
`RadiusUsername_utf` | `string` (UTF8) | Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4).
`NtUsername_utf` | `string` (UTF8) | Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5).
`NumLogin_u32` | `number` (uint32) | Number of total logins of the user
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="setuser"></a>
## "SetUser" RPC API - Change User Settings
### Description
Change User Settings. Use this to change user settings that is registered on the security account database of the currently managed Virtual Hub. The user settings that can be changed using this API are the three items that are specified when a new user is created using the CreateUser API: Group Name, Full Name, and Description. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetUser",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "GroupName_str": "groupname",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "ExpireTime_dt": "2020-08-01T12:24:36.123",
    "AuthType_u32": 0,
    "Auth_Password_str": "auth_password",
    "UserX_bin": "SGVsbG8gV29ybGQ=",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "CommonName_utf": "auth_rootcert_commonname",
    "RadiusUsername_utf": "auth_radius_radiususername",
    "NtUsername_utf": "auth_nt_ntusername",
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "GroupName_str": "groupname",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "CreatedTime_dt": "2020-08-01T12:24:36.123",
    "UpdatedTime_dt": "2020-08-01T12:24:36.123",
    "ExpireTime_dt": "2020-08-01T12:24:36.123",
    "AuthType_u32": 0,
    "Auth_Password_str": "auth_password",
    "UserX_bin": "SGVsbG8gV29ybGQ=",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "CommonName_utf": "auth_rootcert_commonname",
    "RadiusUsername_utf": "auth_radius_radiususername",
    "NtUsername_utf": "auth_nt_ntusername",
    "NumLogin_u32": 0,
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | Specify the user name of the user
`GroupName_str` | `string` (ASCII) | Assigned group name for the user
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the user, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional User Description
`CreatedTime_dt` | `Date` | Creation date and time
`UpdatedTime_dt` | `Date` | Last modified date and time
`ExpireTime_dt` | `Date` | Expiration date and time
`AuthType_u32` | `number` (enum) | Authentication method of the user<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: Password authentication<BR>`2`: User certificate authentication<BR>`3`: Root certificate which is issued by trusted Certificate Authority<BR>`4`: Radius authentication<BR>`5`: Windows NT authentication
`Auth_Password_str` | `string` (ASCII) | User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations.
`UserX_bin` | `string` (Base64 binary) | User certificate, valid only if AuthType_u32 == UserCert(2).
`Serial_bin` | `string` (Base64 binary) | Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3).
`CommonName_utf` | `string` (UTF8) | Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3).
`RadiusUsername_utf` | `string` (UTF8) | Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4).
`NtUsername_utf` | `string` (UTF8) | Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5).
`NumLogin_u32` | `number` (uint32) | Number of total logins of the user
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="getuser"></a>
## "GetUser" RPC API - Get User Settings
### Description
Get User Settings. Use this to get user settings information that is registered on the security account database of the currently managed Virtual Hub. The information that you can get using this API are User Name, Full Name, Group Name, Expiration Date, Security Policy, and Auth Type, as well as parameters that are specified as auth type attributes and the statistical data of that user. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetUser",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "GroupName_str": "groupname",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "CreatedTime_dt": "2020-08-01T12:24:36.123",
    "UpdatedTime_dt": "2020-08-01T12:24:36.123",
    "ExpireTime_dt": "2020-08-01T12:24:36.123",
    "AuthType_u32": 0,
    "Auth_Password_str": "auth_password",
    "UserX_bin": "SGVsbG8gV29ybGQ=",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "CommonName_utf": "auth_rootcert_commonname",
    "RadiusUsername_utf": "auth_radius_radiususername",
    "NtUsername_utf": "auth_nt_ntusername",
    "NumLogin_u32": 0,
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | Specify the user name of the user
`GroupName_str` | `string` (ASCII) | Assigned group name for the user
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the user, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional User Description
`CreatedTime_dt` | `Date` | Creation date and time
`UpdatedTime_dt` | `Date` | Last modified date and time
`ExpireTime_dt` | `Date` | Expiration date and time
`AuthType_u32` | `number` (enum) | Authentication method of the user<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: Password authentication<BR>`2`: User certificate authentication<BR>`3`: Root certificate which is issued by trusted Certificate Authority<BR>`4`: Radius authentication<BR>`5`: Windows NT authentication
`Auth_Password_str` | `string` (ASCII) | User password, valid only if AuthType_u32 == Password(1). Valid only to create or set operations.
`UserX_bin` | `string` (Base64 binary) | User certificate, valid only if AuthType_u32 == UserCert(2).
`Serial_bin` | `string` (Base64 binary) | Certificate Serial Number, optional, valid only if AuthType_u32 == RootCert(3).
`CommonName_utf` | `string` (UTF8) | Certificate Common Name, optional, valid only if AuthType_u32 == RootCert(3).
`RadiusUsername_utf` | `string` (UTF8) | Username in RADIUS server, optional, valid only if AuthType_u32 == Radius(4).
`NtUsername_utf` | `string` (UTF8) | Username in NT Domain server, optional, valid only if AuthType_u32 == NT(5).
`NumLogin_u32` | `number` (uint32) | Number of total logins of the user
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="deleteuser"></a>
## "DeleteUser" RPC API - Delete a user
### Description
Delete a user. Use this to delete a user that is registered on the security account database of the currently managed Virtual Hub. By deleting the user, that user will no long be able to connect to the Virtual Hub. You can use the SetUser API to set the user's security policy to deny access instead of deleting a user, set the user to be temporarily denied from logging in. To get the list of currently registered users, use the EnumUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteUser",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | User or group name

***
<a id="enumuser"></a>
## "EnumUser" RPC API - Get List of Users
### Description
Get List of Users. Use this to get a list of users that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumUser",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "UserList": [
      {
        "Name_str": "name",
        "GroupName_str": "groupname",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "AuthType_u32": 0,
        "NumLogin_u32": 0,
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "DenyAccess_bool": false,
        "IsTrafficFilled_bool": false,
        "IsExpiresFilled_bool": false,
        "Expires_dt": "2020-08-01T12:24:36.123",
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      },
      {
        "Name_str": "name",
        "GroupName_str": "groupname",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "AuthType_u32": 0,
        "NumLogin_u32": 0,
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "DenyAccess_bool": false,
        "IsTrafficFilled_bool": false,
        "IsExpiresFilled_bool": false,
        "Expires_dt": "2020-08-01T12:24:36.123",
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      },
      {
        "Name_str": "name",
        "GroupName_str": "groupname",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "AuthType_u32": 0,
        "NumLogin_u32": 0,
        "LastLoginTime_dt": "2020-08-01T12:24:36.123",
        "DenyAccess_bool": false,
        "IsTrafficFilled_bool": false,
        "IsExpiresFilled_bool": false,
        "Expires_dt": "2020-08-01T12:24:36.123",
        "Ex.Recv.BroadcastBytes_u64": 0,
        "Ex.Recv.BroadcastCount_u64": 0,
        "Ex.Recv.UnicastBytes_u64": 0,
        "Ex.Recv.UnicastCount_u64": 0,
        "Ex.Send.BroadcastBytes_u64": 0,
        "Ex.Send.BroadcastCount_u64": 0,
        "Ex.Send.UnicastBytes_u64": 0,
        "Ex.Send.UnicastCount_u64": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`UserList` | `Array object` | User list
`Name_str` | `string` (ASCII) | User name
`GroupName_str` | `string` (ASCII) | Group name
`Realname_utf` | `string` (UTF8) | Real name
`Note_utf` | `string` (UTF8) | Note
`AuthType_u32` | `number` (enum) | Authentication method<BR>Values:<BR>`0`: Anonymous authentication<BR>`1`: Password authentication<BR>`2`: User certificate authentication<BR>`3`: Root certificate which is issued by trusted Certificate Authority<BR>`4`: Radius authentication<BR>`5`: Windows NT authentication
`NumLogin_u32` | `number` (uint32) | Number of logins
`LastLoginTime_dt` | `Date` | Last login date and time
`DenyAccess_bool` | `boolean` | Access denied
`IsTrafficFilled_bool` | `boolean` | Flag of whether the traffic variable is set
`IsExpiresFilled_bool` | `boolean` | Flag of whether expiration date variable is set
`Expires_dt` | `Date` | Expiration date
`Ex.Recv.BroadcastBytes_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Ex.Recv.BroadcastCount_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Ex.Recv.UnicastBytes_u64` | `number` (uint64) | Unicast count (Recv)
`Ex.Recv.UnicastCount_u64` | `number` (uint64) | Unicast bytes (Recv)
`Ex.Send.BroadcastBytes_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Ex.Send.BroadcastCount_u64` | `number` (uint64) | Broadcast bytes (Send)
`Ex.Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Ex.Send.UnicastCount_u64` | `number` (uint64) | Unicast bytes (Send)

***
<a id="creategroup"></a>
## "CreateGroup" RPC API - Create Group
### Description
Create Group. Use this to create a new group in the security account database of the currently managed Virtual Hub. You can register multiple users in a group. To register users in a group use the SetUser API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "CreateGroup",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | The group name
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the group, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional, specify a description of the group
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="setgroup"></a>
## "SetGroup" RPC API - Set group settings
### Description
Set group settings. Use this to set group settings that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetGroup",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | The group name
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the group, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional, specify a description of the group
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="getgroup"></a>
## "GetGroup" RPC API - Get Group Setting (Sync mode)
### Description
Get Group Setting (Sync mode). Use this to get the setting of a group that is registered on the security account database of the currently managed Virtual Hub. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetGroup",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Realname_utf": "realname",
    "Note_utf": "note",
    "Recv.BroadcastBytes_u64": 0,
    "Recv.BroadcastCount_u64": 0,
    "Recv.UnicastBytes_u64": 0,
    "Recv.UnicastCount_u64": 0,
    "Send.BroadcastBytes_u64": 0,
    "Send.BroadcastCount_u64": 0,
    "Send.UnicastBytes_u64": 0,
    "Send.UnicastCount_u64": 0,
    "UsePolicy_bool": false,
    "policy:Access_bool": false,
    "policy:DHCPFilter_bool": false,
    "policy:DHCPNoServer_bool": false,
    "policy:DHCPForce_bool": false,
    "policy:NoBridge_bool": false,
    "policy:NoRouting_bool": false,
    "policy:CheckMac_bool": false,
    "policy:CheckIP_bool": false,
    "policy:ArpDhcpOnly_bool": false,
    "policy:PrivacyFilter_bool": false,
    "policy:NoServer_bool": false,
    "policy:NoBroadcastLimiter_bool": false,
    "policy:MonitorPort_bool": false,
    "policy:MaxConnection_u32": 0,
    "policy:TimeOut_u32": 0,
    "policy:MaxMac_u32": 0,
    "policy:MaxIP_u32": 0,
    "policy:MaxUpload_u32": 0,
    "policy:MaxDownload_u32": 0,
    "policy:FixPassword_bool": false,
    "policy:MultiLogins_u32": 0,
    "policy:NoQoS_bool": false,
    "policy:RSandRAFilter_bool": false,
    "policy:RAFilter_bool": false,
    "policy:DHCPv6Filter_bool": false,
    "policy:DHCPv6NoServer_bool": false,
    "policy:NoRoutingV6_bool": false,
    "policy:CheckIPv6_bool": false,
    "policy:NoServerV6_bool": false,
    "policy:MaxIPv6_u32": 0,
    "policy:NoSavePassword_bool": false,
    "policy:AutoDisconnect_u32": 0,
    "policy:FilterIPv4_bool": false,
    "policy:FilterIPv6_bool": false,
    "policy:FilterNonIP_bool": false,
    "policy:NoIPv6DefaultRouterInRA_bool": false,
    "policy:NoIPv6DefaultRouterInRAWhenIPv6_bool": false,
    "policy:VLanId_u32": 0,
    "policy:Ver3_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | The group name
`Realname_utf` | `string` (UTF8) | Optional real name (full name) of the group, allow using any Unicode characters
`Note_utf` | `string` (UTF8) | Optional, specify a description of the group
`Recv.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Recv)
`Recv.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Recv)
`Recv.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Recv)
`Recv.UnicastCount_u64` | `number` (uint64) | Unicast count (Recv)
`Send.BroadcastBytes_u64` | `number` (uint64) | Broadcast bytes (Send)
`Send.BroadcastCount_u64` | `number` (uint64) | Number of broadcast packets (Send)
`Send.UnicastBytes_u64` | `number` (uint64) | Unicast bytes (Send)
`Send.UnicastCount_u64` | `number` (uint64) | Unicast count (Send)
`UsePolicy_bool` | `boolean` | The flag whether to use security policy
`policy:Access_bool` | `boolean` | Security policy: Allow Access. The users, which this policy value is true, have permission to make VPN connection to VPN Server.
`policy:DHCPFilter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv4). All IPv4 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPNoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv4). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv4 addresses to DHCP clients.
`policy:DHCPForce_bool` | `boolean` | Security policy: Enforce DHCP Allocated IP Addresses (IPv4). Computers in sessions that have this policy setting will only be able to use IPv4 addresses allocated by a DHCP server on the virtual network side.
`policy:NoBridge_bool` | `boolean` | Security policy: Deny Bridge Operation. Bridge-mode connections are denied for user sessions that have this policy setting. Even in cases when the Ethernet Bridge is configured in the client side, communication will not be possible.
`policy:NoRouting_bool` | `boolean` | Security policy: Deny Routing Operation (IPv4). IPv4 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckMac_bool` | `boolean` | Security policy: Deny MAC Addresses Duplication. The use of duplicating MAC addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:CheckIP_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv4). The use of duplicating IPv4 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:ArpDhcpOnly_bool` | `boolean` | Security policy: Deny Non-ARP / Non-DHCP / Non-ICMPv6 broadcasts. The sending or receiving of broadcast packets that are not ARP protocol, DHCP protocol, nor ICMPv6 on the virtual network will not be allowed for sessions with this policy setting.
`policy:PrivacyFilter_bool` | `boolean` | Security policy: Privacy Filter Mode. All direct communication between sessions with the privacy filter mode policy setting will be filtered.
`policy:NoServer_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv4). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv4.
`policy:NoBroadcastLimiter_bool` | `boolean` | Security policy: Unlimited Number of Broadcasts. If a computer of a session with this policy setting sends broadcast packets of a number unusually larger than what would be considered normal on the virtual network, there will be no automatic limiting.
`policy:MonitorPort_bool` | `boolean` | Security policy: Allow Monitoring Mode. Users with this policy setting will be granted to connect to the Virtual Hub in Monitoring Mode. Sessions in Monitoring Mode are able to monitor (tap) all packets flowing through the Virtual Hub.
`policy:MaxConnection_u32` | `number` (uint32) | Security policy: Maximum Number of TCP Connections. For sessions with this policy setting, this sets the maximum number of physical TCP connections consists in a physical VPN session.
`policy:TimeOut_u32` | `number` (uint32) | Security policy: Time-out Period. For sessions with this policy setting, this sets, in seconds, the time-out period to wait before disconnecting a session when communication trouble occurs between the VPN Client / VPN Server.
`policy:MaxMac_u32` | `number` (uint32) | Security policy: Maximum Number of MAC Addresses. For sessions with this policy setting, this limits the number of MAC addresses per session.
`policy:MaxIP_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv4). For sessions with this policy setting, this specifies the number of IPv4 addresses that can be registered for a single session.
`policy:MaxUpload_u32` | `number` (uint32) | Security policy: Upload Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the inwards direction from outside to inside the Virtual Hub.
`policy:MaxDownload_u32` | `number` (uint32) | Security policy: Download Bandwidth. For sessions with this policy setting, this limits the traffic bandwidth that is in the outwards direction from inside the Virtual Hub to outside the Virtual Hub.
`policy:FixPassword_bool` | `boolean` | Security policy: Deny Changing Password. The users which use password authentication with this policy setting are not allowed to change their own password from the VPN Client Manager or similar.
`policy:MultiLogins_u32` | `number` (uint32) | Security policy: Maximum Number of Multiple Logins. Users with this policy setting are unable to have more than this number of concurrent logins. Bridge Mode sessions are not subjects to this policy.
`policy:NoQoS_bool` | `boolean` | Security policy: Deny VoIP / QoS Function. Users with this security policy are unable to use VoIP / QoS functions in VPN connection sessions.
`policy:RSandRAFilter_bool` | `boolean` | Security policy: Filter RS / RA Packets (IPv6). All ICMPv6 packets which the message-type is 133 (Router Solicitation) or 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, an IPv6 client will be unable to use IPv6 address prefix auto detection and IPv6 default gateway auto detection.
`policy:RAFilter_bool` | `boolean` | Security policy: Filter RA Packets (IPv6). All ICMPv6 packets which the message-type is 134 (Router Advertisement) in sessions defined this policy will be filtered. As a result, a malicious users will be unable to spread illegal IPv6 prefix or default gateway advertisements on the network.
`policy:DHCPv6Filter_bool` | `boolean` | Security policy: Filter DHCP Packets (IPv6). All IPv6 DHCP packets in sessions defined this policy will be filtered.
`policy:DHCPv6NoServer_bool` | `boolean` | Security policy: Disallow DHCP Server Operation (IPv6). Computers connected to sessions that have this policy setting will not be allowed to become a DHCP server and distribute IPv6 addresses to DHCP clients.
`policy:NoRoutingV6_bool` | `boolean` | Security policy: Deny Routing Operation (IPv6). IPv6 routing will be denied for sessions that have this policy setting. Even in the case where the IP router is operating on the user client side, communication will not be possible.
`policy:CheckIPv6_bool` | `boolean` | Security policy: Deny IP Address Duplication (IPv6). The use of duplicating IPv6 addresses that are in use by computers of different sessions cannot be used by sessions with this policy setting.
`policy:NoServerV6_bool` | `boolean` | Security policy: Deny Operation as TCP/IP Server (IPv6). Computers of sessions with this policy setting can't listen and accept TCP/IP connections in IPv6.
`policy:MaxIPv6_u32` | `number` (uint32) | Security policy: Maximum Number of IP Addresses (IPv6). For sessions with this policy setting, this specifies the number of IPv6 addresses that can be registered for a single session.
`policy:NoSavePassword_bool` | `boolean` | Security policy: Disallow Password Save in VPN Client. For users with this policy setting, when the user is using *standard* password authentication, the user will be unable to save the password in VPN Client. The user will be required to input passwords for every time to connect a VPN. This will improve the security. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:AutoDisconnect_u32` | `number` (uint32) | Security policy: VPN Client Automatic Disconnect. For users with this policy setting, a user's VPN session will be disconnected automatically after the specific period will elapse. In this case no automatic re-connection will be performed. This can prevent a lot of inactive VPN Sessions. If this policy is enabled, VPN Client Version 2.0 will be denied to access.
`policy:FilterIPv4_bool` | `boolean` | Security policy: Filter All IPv4 Packets. All IPv4 and ARP packets in sessions defined this policy will be filtered.
`policy:FilterIPv6_bool` | `boolean` | Security policy: Filter All IPv6 Packets. All IPv6 packets in sessions defined this policy will be filtered.
`policy:FilterNonIP_bool` | `boolean` | Security policy: Filter All Non-IP Packets. All non-IP packets in sessions defined this policy will be filtered. "Non-IP packet" mean a packet which is not IPv4, ARP nor IPv6. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets.
`policy:NoIPv6DefaultRouterInRA_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA. In all VPN Sessions defines this policy, any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:NoIPv6DefaultRouterInRAWhenIPv6_bool` | `boolean` | Security policy: No Default-Router on IPv6 RA (physical IPv6). In all VPN Sessions defines this policy (only when the physical communication protocol between VPN Client / VPN Bridge and VPN Server is IPv6), any IPv6 RA (Router Advertisement) packet with non-zero value in the router-lifetime will set to zero-value. This is effective to avoid the horrible behavior from the IPv6 routing confusion which is caused by the VPN client's attempts to use the remote-side IPv6 router as its local IPv6 router.
`policy:VLanId_u32` | `number` (uint32) | Security policy: VLAN ID (IEEE802.1Q). You can specify the VLAN ID on the security policy. All VPN Sessions defines this policy, all Ethernet packets toward the Virtual Hub from the user will be inserted a VLAN tag (IEEE 802.1Q) with the VLAN ID. The user can also receive only packets with a VLAN tag which has the same VLAN ID. (Receiving process removes the VLAN tag automatically.) Any Ethernet packets with any other VLAN IDs or non-VLAN packets will not be received. All VPN Sessions without this policy definition can send / receive any kinds of Ethernet packets regardless of VLAN tags, and VLAN tags are not inserted or removed automatically. Any tagged-VLAN packets via the Virtual Hub will be regarded as non-IP packets. Therefore, tagged-VLAN packets are not subjects for IPv4 / IPv6 security policies, access lists nor other IPv4 / IPv6 specific deep processing.
`policy:Ver3_bool` | `boolean` | Security policy: Whether version 3.0 (must be true)

***
<a id="deletegroup"></a>
## "DeleteGroup" RPC API - Delete User from Group
### Description
Delete User from Group. Use this to delete a specified user from the group that is registered on the security account database of the currently managed Virtual Hub. By deleting a user from the group, that user becomes unassigned. To get the list of currently registered groups, use the EnumGroup API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteGroup",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | User or group name

***
<a id="enumgroup"></a>
## "EnumGroup" RPC API - Get List of Groups
### Description
Get List of Groups. Use this to get a list of groups that are registered on the security account database of the currently managed Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a member server on a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumGroup",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "GroupList": [
      {
        "Name_str": "name",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "NumUsers_u32": 0,
        "DenyAccess_bool": false
      },
      {
        "Name_str": "name",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "NumUsers_u32": 0,
        "DenyAccess_bool": false
      },
      {
        "Name_str": "name",
        "Realname_utf": "realname",
        "Note_utf": "note",
        "NumUsers_u32": 0,
        "DenyAccess_bool": false
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`GroupList` | `Array object` | Group list
`Name_str` | `string` (ASCII) | User name
`Realname_utf` | `string` (UTF8) | Real name
`Note_utf` | `string` (UTF8) | Note
`NumUsers_u32` | `number` (uint32) | Number of users
`DenyAccess_bool` | `boolean` | Access denied

***
<a id="enumsession"></a>
## "EnumSession" RPC API - Get List of Connected VPN Sessions
### Description
Get List of Connected VPN Sessions. Use this to get a list of the sessions connected to the Virtual Hub currently being managed. In the list of sessions, the following information will be obtained for each connection: Session Name, Session Site, User Name, Source Host Name, TCP Connection, Transfer Bytes and Transfer Packets. If the currently connected VPN Server is a cluster controller and the currently managed Virtual Hub is a static Virtual Hub, you can get an all-linked-together list of all sessions connected to that Virtual Hub on all cluster members. In all other cases, only the list of sessions that are actually connected to the currently managed VPN Server will be obtained.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumSession",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "SessionList": [
      {
        "Name_str": "name",
        "RemoteSession_bool": false,
        "RemoteHostname_str": "remotehostname",
        "Username_str": "username",
        "ClientIP_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "MaxNumTcp_u32": 0,
        "CurrentNumTcp_u32": 0,
        "PacketSize_u64": 0,
        "PacketNum_u64": 0,
        "LinkMode_bool": false,
        "SecureNATMode_bool": false,
        "BridgeMode_bool": false,
        "Layer3Mode_bool": false,
        "Client_BridgeMode_bool": false,
        "Client_MonitorMode_bool": false,
        "VLanId_u32": 0,
        "UniqueId_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123"
      },
      {
        "Name_str": "name",
        "RemoteSession_bool": false,
        "RemoteHostname_str": "remotehostname",
        "Username_str": "username",
        "ClientIP_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "MaxNumTcp_u32": 0,
        "CurrentNumTcp_u32": 0,
        "PacketSize_u64": 0,
        "PacketNum_u64": 0,
        "LinkMode_bool": false,
        "SecureNATMode_bool": false,
        "BridgeMode_bool": false,
        "Layer3Mode_bool": false,
        "Client_BridgeMode_bool": false,
        "Client_MonitorMode_bool": false,
        "VLanId_u32": 0,
        "UniqueId_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123"
      },
      {
        "Name_str": "name",
        "RemoteSession_bool": false,
        "RemoteHostname_str": "remotehostname",
        "Username_str": "username",
        "ClientIP_ip": "192.168.0.1",
        "Hostname_str": "hostname",
        "MaxNumTcp_u32": 0,
        "CurrentNumTcp_u32": 0,
        "PacketSize_u64": 0,
        "PacketNum_u64": 0,
        "LinkMode_bool": false,
        "SecureNATMode_bool": false,
        "BridgeMode_bool": false,
        "Layer3Mode_bool": false,
        "Client_BridgeMode_bool": false,
        "Client_MonitorMode_bool": false,
        "VLanId_u32": 0,
        "UniqueId_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`SessionList` | `Array object` | VPN sessions list
`Name_str` | `string` (ASCII) | Session name
`RemoteSession_bool` | `boolean` | Remote session
`RemoteHostname_str` | `string` (ASCII) | Remote server name
`Username_str` | `string` (ASCII) | User name
`ClientIP_ip` | `string` (IP address) | IP address
`Hostname_str` | `string` (ASCII) | Host name
`MaxNumTcp_u32` | `number` (uint32) | Maximum number of underlying TCP connections
`CurrentNumTcp_u32` | `number` (uint32) | Number of current underlying TCP connections
`PacketSize_u64` | `number` (uint64) | Packet size transmitted
`PacketNum_u64` | `number` (uint64) | Number of packets transmitted
`LinkMode_bool` | `boolean` | Is a Cascade VPN session
`SecureNATMode_bool` | `boolean` | Is a SecureNAT VPN session
`BridgeMode_bool` | `boolean` | Is the VPN session for Local Bridge
`Layer3Mode_bool` | `boolean` | Is a Layer-3 Switch VPN session
`Client_BridgeMode_bool` | `boolean` | Is in Bridge Mode
`Client_MonitorMode_bool` | `boolean` | Is in Monitor Mode
`VLanId_u32` | `number` (uint32) | VLAN ID
`UniqueId_bin` | `string` (Base64 binary) | Unique ID of the VPN Session
`CreatedTime_dt` | `Date` | Creation date and time
`LastCommTime_dt` | `Date` | Last communication date and time

***
<a id="getsessionstatus"></a>
## "GetSessionStatus" RPC API - Get Session Status
### Description
Get Session Status. Use this to specify a session currently connected to the currently managed Virtual Hub and get the session information. The session status includes the following: source host name and user name, version information, time information, number of TCP connections, communication parameters, session key, statistical information on data transferred, and other client and server information. To get the list of currently connected sessions, use the EnumSession API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetSessionStatus",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name",
    "Username_str": "username",
    "RealUsername_str": "realusername",
    "GroupName_str": "groupname",
    "LinkMode_bool": false,
    "Client_Ip_Address_ip": "192.168.0.1",
    "SessionStatus_ClientHostName_str": "clienthostname",
    "Active_bool": false,
    "Connected_bool": false,
    "SessionStatus_u32": 0,
    "ServerName_str": "servername",
    "ServerPort_u32": 0,
    "ServerProductName_str": "serverproductname",
    "ServerProductVer_u32": 0,
    "ServerProductBuild_u32": 0,
    "StartTime_dt": "2020-08-01T12:24:36.123",
    "FirstConnectionEstablisiedTime_dt": "2020-08-01T12:24:36.123",
    "CurrentConnectionEstablishTime_dt": "2020-08-01T12:24:36.123",
    "NumConnectionsEatablished_u32": 0,
    "HalfConnection_bool": false,
    "QoS_bool": false,
    "MaxTcpConnections_u32": 0,
    "NumTcpConnections_u32": 0,
    "NumTcpConnectionsUpload_u32": 0,
    "NumTcpConnectionsDownload_u32": 0,
    "UseEncrypt_bool": false,
    "CipherName_str": "ciphername",
    "UseCompress_bool": false,
    "IsRUDPSession_bool": false,
    "UnderlayProtocol_str": "underlayprotocol",
    "IsUdpAccelerationEnabled_bool": false,
    "IsUsingUdpAcceleration_bool": false,
    "SessionName_str": "sessionname",
    "ConnectionName_str": "connectionname",
    "SessionKey_bin": "SGVsbG8gV29ybGQ=",
    "TotalSendSize_u64": 0,
    "TotalRecvSize_u64": 0,
    "TotalSendSizeReal_u64": 0,
    "TotalRecvSizeReal_u64": 0,
    "IsBridgeMode_bool": false,
    "IsMonitorMode_bool": false,
    "VLanId_u32": 0,
    "ClientProductName_str": "clientproductname",
    "ClientProductVer_u32": 0,
    "ClientProductBuild_u32": 0,
    "ClientOsName_str": "clientosname",
    "ClientOsVer_str": "clientosver",
    "ClientOsProductId_str": "clientosproductid",
    "ClientHostname_str": "clienthostname",
    "UniqueId_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | VPN session name
`Username_str` | `string` (ASCII) | User name
`RealUsername_str` | `string` (ASCII) | Real user name which was used for the authentication
`GroupName_str` | `string` (ASCII) | Group name
`LinkMode_bool` | `boolean` | Is Cascade Session
`Client_Ip_Address_ip` | `string` (IP address) | Client IP address
`SessionStatus_ClientHostName_str` | `string` (ASCII) | Client host name
`Active_bool` | `boolean` | Operation flag
`Connected_bool` | `boolean` | Connected flag
`SessionStatus_u32` | `number` (enum) | State of the client session<BR>Values:<BR>`0`: Connecting<BR>`1`: Negotiating<BR>`2`: During user authentication<BR>`3`: Connection complete<BR>`4`: Wait to retry<BR>`5`: Idle state
`ServerName_str` | `string` (ASCII) | Server name
`ServerPort_u32` | `number` (uint32) | Port number of the server
`ServerProductName_str` | `string` (ASCII) | Server product name
`ServerProductVer_u32` | `number` (uint32) | Server product version
`ServerProductBuild_u32` | `number` (uint32) | Server product build number
`StartTime_dt` | `Date` | Connection start time
`FirstConnectionEstablisiedTime_dt` | `Date` | Connection completion time of the first connection
`CurrentConnectionEstablishTime_dt` | `Date` | Connection completion time of this connection
`NumConnectionsEatablished_u32` | `number` (uint32) | Number of connections have been established so far
`HalfConnection_bool` | `boolean` | Half-connection
`QoS_bool` | `boolean` | VoIP / QoS
`MaxTcpConnections_u32` | `number` (uint32) | Maximum number of the underlying TCP connections
`NumTcpConnections_u32` | `number` (uint32) | Number of current underlying TCP connections
`NumTcpConnectionsUpload_u32` | `number` (uint32) | Number of inbound underlying connections
`NumTcpConnectionsDownload_u32` | `number` (uint32) | Number of outbound underlying connections
`UseEncrypt_bool` | `boolean` | Use of encryption
`CipherName_str` | `string` (ASCII) | Cipher algorithm name
`UseCompress_bool` | `boolean` | Use of compression
`IsRUDPSession_bool` | `boolean` | Is R-UDP session
`UnderlayProtocol_str` | `string` (ASCII) | Physical underlying communication protocol
`IsUdpAccelerationEnabled_bool` | `boolean` | The UDP acceleration is enabled
`IsUsingUdpAcceleration_bool` | `boolean` | Using the UDP acceleration function
`SessionName_str` | `string` (ASCII) | VPN session name
`ConnectionName_str` | `string` (ASCII) | Connection name
`SessionKey_bin` | `string` (Base64 binary) | Session key
`TotalSendSize_u64` | `number` (uint64) | Total transmitted data size
`TotalRecvSize_u64` | `number` (uint64) | Total received data size
`TotalSendSizeReal_u64` | `number` (uint64) | Total transmitted data size (no compression)
`TotalRecvSizeReal_u64` | `number` (uint64) | Total received data size (no compression)
`IsBridgeMode_bool` | `boolean` | Is Bridge Mode
`IsMonitorMode_bool` | `boolean` | Is Monitor mode
`VLanId_u32` | `number` (uint32) | VLAN ID
`ClientProductName_str` | `string` (ASCII) | Client product name
`ClientProductVer_u32` | `number` (uint32) | Client version
`ClientProductBuild_u32` | `number` (uint32) | Client build number
`ClientOsName_str` | `string` (ASCII) | Client OS name
`ClientOsVer_str` | `string` (ASCII) | Client OS version
`ClientOsProductId_str` | `string` (ASCII) | Client OS Product ID
`ClientHostname_str` | `string` (ASCII) | Client host name
`UniqueId_bin` | `string` (Base64 binary) | Unique ID

***
<a id="deletesession"></a>
## "DeleteSession" RPC API - Disconnect Session
### Description
Disconnect Session. Use this to specify a session currently connected to the currently managed Virtual Hub and forcefully disconnect that session using manager privileges. Note that when communication is disconnected by settings on the source client side and the automatically reconnect option is enabled, it is possible that the client will reconnect. To get the list of currently connected sessions, use the EnumSession API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteSession",
  "params": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Name_str` | `string` (ASCII) | Session name

***
<a id="enummactable"></a>
## "EnumMacTable" RPC API - Get the MAC Address Table Database
### Description
Get the MAC Address Table Database. Use this to get the MAC address table database that is held by the currently managed Virtual Hub. The MAC address table database is a table that the Virtual Hub requires to perform the action of switching Ethernet frames and the Virtual Hub decides the sorting destination session of each Ethernet frame based on the MAC address table database. The MAC address database is built by the Virtual Hub automatically analyzing the contents of the communication.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumMacTable",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "MacTable": [
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname",
        "VlanId_u32": 0
      },
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname",
        "VlanId_u32": 0
      },
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname",
        "VlanId_u32": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`MacTable` | `Array object` | MAC table
`Key_u32` | `number` (uint32) | Key ID
`SessionName_str` | `string` (ASCII) | Session name
`MacAddress_bin` | `string` (Base64 binary) | MAC address
`CreatedTime_dt` | `Date` | Creation date and time
`UpdatedTime_dt` | `Date` | Updating date
`RemoteItem_bool` | `boolean` | Remote items
`RemoteHostname_str` | `string` (ASCII) | Remote host name
`VlanId_u32` | `number` (uint32) | VLAN ID

***
<a id="deletemactable"></a>
## "DeleteMacTable" RPC API - Delete MAC Address Table Entry
### Description
Delete MAC Address Table Entry. Use this API to operate the MAC address table database held by the currently managed Virtual Hub and delete a specified MAC address table entry from the database. To get the contents of the current MAC address table database use the EnumMacTable API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteMacTable",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID

***
<a id="enumiptable"></a>
## "EnumIpTable" RPC API - Get the IP Address Table Database
### Description
Get the IP Address Table Database. Use this to get the IP address table database that is held by the currently managed Virtual Hub. The IP address table database is a table that is automatically generated by analyzing the contents of communication so that the Virtual Hub can always know which session is using which IP address and it is frequently used by the engine that applies the Virtual Hub security policy. By specifying the session name you can get the IP address table entry that has been associated with that session.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumIpTable",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "IpTable": [
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "IpAddress_ip": "192.168.0.1",
        "DhcpAllocated_bool": false,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname"
      },
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "IpAddress_ip": "192.168.0.1",
        "DhcpAllocated_bool": false,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname"
      },
      {
        "Key_u32": 0,
        "SessionName_str": "sessionname",
        "IpAddress_ip": "192.168.0.1",
        "DhcpAllocated_bool": false,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "UpdatedTime_dt": "2020-08-01T12:24:36.123",
        "RemoteItem_bool": false,
        "RemoteHostname_str": "remotehostname"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`IpTable` | `Array object` | MAC table
`Key_u32` | `number` (uint32) | Key ID
`SessionName_str` | `string` (ASCII) | Session name
`IpAddress_ip` | `string` (IP address) | IP address
`DhcpAllocated_bool` | `boolean` | Assigned by the DHCP
`CreatedTime_dt` | `Date` | Creation date and time
`UpdatedTime_dt` | `Date` | Updating date
`RemoteItem_bool` | `boolean` | Remote items
`RemoteHostname_str` | `string` (ASCII) | Remote host name

***
<a id="deleteiptable"></a>
## "DeleteIpTable" RPC API - Delete IP Address Table Entry
### Description
Delete IP Address Table Entry. Use this API to operate the IP address table database held by the currently managed Virtual Hub and delete a specified IP address table entry from the database. To get the contents of the current IP address table database use the EnumIpTable API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteIpTable",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID

***
<a id="setkeep"></a>
## "SetKeep" RPC API - Set the Keep Alive Internet Connection Function
### Description
Set the Keep Alive Internet Connection Function. Use this to set the destination host name etc. of the Keep Alive Internet Connection Function. For network connection environments where connections will automatically be disconnected where there are periods of no communication that are longer than a set period, by using the Keep Alive Internet Connection Function, it is possible to keep alive the Internet connection by sending packets to a nominated server on the Internet at set intervals. When using this API, you can specify the following: Host Name, Port Number, Packet Send Interval, and Protocol. Packets sent to keep alive the Internet connection will have random content and personal information that could identify a computer or user is not sent. You can use the SetKeep API to enable/disable the Keep Alive Internet Connection Function. To execute this API on a VPN Server or VPN Bridge, you must have administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetKeep",
  "params": {
    "UseKeepConnect_bool": false,
    "KeepConnectHost_str": "keepconnecthost",
    "KeepConnectPort_u32": 0,
    "KeepConnectProtocol_u32": 0,
    "KeepConnectInterval_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "UseKeepConnect_bool": false,
    "KeepConnectHost_str": "keepconnecthost",
    "KeepConnectPort_u32": 0,
    "KeepConnectProtocol_u32": 0,
    "KeepConnectInterval_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`UseKeepConnect_bool` | `boolean` | The flag to enable keep-alive to the Internet
`KeepConnectHost_str` | `string` (ASCII) | Specify the host name or IP address of the destination
`KeepConnectPort_u32` | `number` (uint32) | Specify the port number of the destination
`KeepConnectProtocol_u32` | `number` (enum) | Protocol type<BR>Values:<BR>`0`: TCP<BR>`1`: UDP
`KeepConnectInterval_u32` | `number` (uint32) | Interval Between Packets Sends (Seconds)

***
<a id="getkeep"></a>
## "GetKeep" RPC API - Get the Keep Alive Internet Connection Function
### Description
Get the Keep Alive Internet Connection Function. Use this to get the current setting contents of the Keep Alive Internet Connection Function. In addition to the destination's Host Name, Port Number, Packet Send Interval and Protocol, you can obtain the current enabled/disabled status of the Keep Alive Internet Connection Function.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetKeep",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "UseKeepConnect_bool": false,
    "KeepConnectHost_str": "keepconnecthost",
    "KeepConnectPort_u32": 0,
    "KeepConnectProtocol_u32": 0,
    "KeepConnectInterval_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`UseKeepConnect_bool` | `boolean` | The flag to enable keep-alive to the Internet
`KeepConnectHost_str` | `string` (ASCII) | Specify the host name or IP address of the destination
`KeepConnectPort_u32` | `number` (uint32) | Specify the port number of the destination
`KeepConnectProtocol_u32` | `number` (enum) | Protocol type<BR>Values:<BR>`0`: TCP<BR>`1`: UDP
`KeepConnectInterval_u32` | `number` (uint32) | Interval Between Packets Sends (Seconds)

***
<a id="enablesecurenat"></a>
## "EnableSecureNAT" RPC API - Enable the Virtual NAT and DHCP Server Function (SecureNAT Function)
### Description
Enable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to enable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub and begin its operation. Before executing this API, you must first check the setting contents of the current Virtual NAT function and DHCP Server function using the SetSecureNATOption API and GetSecureNATOption API. By enabling the SecureNAT function, you can virtually operate a NAT router (IP masquerade) and the DHCP Server function on a virtual network on the Virtual Hub. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrator's permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnableSecureNAT",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name

***
<a id="disablesecurenat"></a>
## "DisableSecureNAT" RPC API - Disable the Virtual NAT and DHCP Server Function (SecureNAT Function)
### Description
Disable the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to disable the Virtual NAT and DHCP Server function (SecureNAT Function) on the currently managed Virtual Hub. By executing this API the Virtual NAT function immediately stops operating and the Virtual DHCP Server function deletes the DHCP lease database and stops the service. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DisableSecureNAT",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name

***
<a id="setsecurenatoption"></a>
## "SetSecureNATOption" RPC API - Change Settings of SecureNAT Function
### Description
Change Settings of SecureNAT Function. Use this to change and save the virtual host network interface settings, virtual NAT function settings and virtual DHCP server settings of the Virtual NAT and DHCP Server function (SecureNAT function) on the currently managed Virtual Hub. The SecureNAT function holds one virtual network adapter on the L2 segment inside the Virtual Hub and it has been assigned a MAC address and an IP address. By doing this, another host connected to the same L2 segment is able to communicate with the SecureNAT virtual host as if it is an actual IP host existing on the network. [Warning about SecureNAT Function] The SecureNAT function is recommended only for system administrators and people with a detailed knowledge of networks. If you use the SecureNAT function correctly, it is possible to achieve a safe form of remote access via a VPN. However when used in the wrong way, it can put the entire network in danger. Anyone who does not have a thorough knowledge of networks and anyone who does not have the network administrators permission must not enable the SecureNAT function. For a detailed explanation of the SecureNAT function, please refer to the VPN Server's manual and online documentation. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetSecureNATOption",
  "params": {
    "RpcHubName_str": "rpchubname",
    "MacAddress_bin": "SGVsbG8gV29ybGQ=",
    "Ip_ip": "192.168.0.1",
    "Mask_ip": "255.255.255.255",
    "UseNat_bool": false,
    "Mtu_u32": 0,
    "NatTcpTimeout_u32": 0,
    "NatUdpTimeout_u32": 0,
    "UseDhcp_bool": false,
    "DhcpLeaseIPStart_ip": "192.168.0.1",
    "DhcpLeaseIPEnd_ip": "192.168.0.1",
    "DhcpSubnetMask_ip": "255.255.255.255",
    "DhcpExpireTimeSpan_u32": 0,
    "DhcpGatewayAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress2_ip": "192.168.0.1",
    "DhcpDomainName_str": "dhcpdomainname",
    "SaveLog_bool": false,
    "ApplyDhcpPushRoutes_bool": false,
    "DhcpPushRoutes_str": "dhcppushroutes"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "RpcHubName_str": "rpchubname",
    "MacAddress_bin": "SGVsbG8gV29ybGQ=",
    "Ip_ip": "192.168.0.1",
    "Mask_ip": "255.255.255.255",
    "UseNat_bool": false,
    "Mtu_u32": 0,
    "NatTcpTimeout_u32": 0,
    "NatUdpTimeout_u32": 0,
    "UseDhcp_bool": false,
    "DhcpLeaseIPStart_ip": "192.168.0.1",
    "DhcpLeaseIPEnd_ip": "192.168.0.1",
    "DhcpSubnetMask_ip": "255.255.255.255",
    "DhcpExpireTimeSpan_u32": 0,
    "DhcpGatewayAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress2_ip": "192.168.0.1",
    "DhcpDomainName_str": "dhcpdomainname",
    "SaveLog_bool": false,
    "ApplyDhcpPushRoutes_bool": false,
    "DhcpPushRoutes_str": "dhcppushroutes"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`RpcHubName_str` | `string` (ASCII) | Target Virtual HUB name
`MacAddress_bin` | `string` (Base64 binary) | MAC address
`Ip_ip` | `string` (IP address) | IP address
`Mask_ip` | `string` (IP address) | Subnet mask
`UseNat_bool` | `boolean` | Use flag of the Virtual NAT function
`Mtu_u32` | `number` (uint32) | MTU value (Standard: 1500)
`NatTcpTimeout_u32` | `number` (uint32) | NAT TCP timeout in seconds
`NatUdpTimeout_u32` | `number` (uint32) | NAT UDP timeout in seconds
`UseDhcp_bool` | `boolean` | Using flag of DHCP function
`DhcpLeaseIPStart_ip` | `string` (IP address) | Specify the start point of the address band to be distributed to the client. (Example: 192.168.30.10)
`DhcpLeaseIPEnd_ip` | `string` (IP address) | Specify the end point of the address band to be distributed to the client. (Example: 192.168.30.200)
`DhcpSubnetMask_ip` | `string` (IP address) | Specify the subnet mask to be specified for the client. (Example: 255.255.255.0)
`DhcpExpireTimeSpan_u32` | `number` (uint32) | Specify the expiration date in second units for leasing an IP address to a client.
`DhcpGatewayAddress_ip` | `string` (IP address) | Specify the IP address of the default gateway to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify 0 or none, then the client will not be notified of the default gateway.
`DhcpDnsServerAddress_ip` | `string` (IP address) | Specify the IP address of the primary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
`DhcpDnsServerAddress2_ip` | `string` (IP address) | Specify the IP address of the secondary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
`DhcpDomainName_str` | `string` (ASCII) | Specify the domain name to be notified to the client. If you specify none, then the client will not be notified of the domain name.
`SaveLog_bool` | `boolean` | Specify whether or not to save the Virtual DHCP Server operation in the Virtual Hub security log. Specify true to save it. This value is interlinked with the Virtual NAT Function log save setting.
`ApplyDhcpPushRoutes_bool` | `boolean` | The flag to enable the DhcpPushRoutes_str field.
`DhcpPushRoutes_str` | `string` (ASCII) | Specify the static routing table to push. Example: "192.168.5.0/255.255.255.0/192.168.4.254, 10.0.0.0/255.0.0.0/192.168.4.253" Split multiple entries (maximum: 64 entries) by comma or space characters. Each entry must be specified in the "IP network address/subnet mask/gateway IP address" format. This Virtual DHCP Server can push the classless static routes (RFC 3442) with DHCP reply messages to VPN clients. Whether or not a VPN client can recognize the classless static routes (RFC 3442) depends on the target VPN client software. SoftEther VPN Client and OpenVPN Client are supporting the classless static routes. On L2TP/IPsec and MS-SSTP protocols, the compatibility depends on the implementation of the client software. You can realize the split tunneling if you clear the default gateway field on the Virtual DHCP Server options. On the client side, L2TP/IPsec and MS-SSTP clients need to be configured not to set up the default gateway for the split tunneling usage. You can also push the classless static routes (RFC 3442) by your existing external DHCP server. In that case, disable the Virtual DHCP Server function on SecureNAT, and you need not to set up the classless routes on this API. See the RFC 3442 to understand the classless routes.

***
<a id="getsecurenatoption"></a>
## "GetSecureNATOption" RPC API - Get Settings of SecureNAT Function
### Description
Get Settings of SecureNAT Function. This API get the registered settings for the SecureNAT function which is set by the SetSecureNATOption API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetSecureNATOption",
  "params": {
    "RpcHubName_str": "rpchubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "RpcHubName_str": "rpchubname",
    "MacAddress_bin": "SGVsbG8gV29ybGQ=",
    "Ip_ip": "192.168.0.1",
    "Mask_ip": "255.255.255.255",
    "UseNat_bool": false,
    "Mtu_u32": 0,
    "NatTcpTimeout_u32": 0,
    "NatUdpTimeout_u32": 0,
    "UseDhcp_bool": false,
    "DhcpLeaseIPStart_ip": "192.168.0.1",
    "DhcpLeaseIPEnd_ip": "192.168.0.1",
    "DhcpSubnetMask_ip": "255.255.255.255",
    "DhcpExpireTimeSpan_u32": 0,
    "DhcpGatewayAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress_ip": "192.168.0.1",
    "DhcpDnsServerAddress2_ip": "192.168.0.1",
    "DhcpDomainName_str": "dhcpdomainname",
    "SaveLog_bool": false,
    "ApplyDhcpPushRoutes_bool": false,
    "DhcpPushRoutes_str": "dhcppushroutes"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`RpcHubName_str` | `string` (ASCII) | Target Virtual HUB name
`MacAddress_bin` | `string` (Base64 binary) | MAC address
`Ip_ip` | `string` (IP address) | IP address
`Mask_ip` | `string` (IP address) | Subnet mask
`UseNat_bool` | `boolean` | Use flag of the Virtual NAT function
`Mtu_u32` | `number` (uint32) | MTU value (Standard: 1500)
`NatTcpTimeout_u32` | `number` (uint32) | NAT TCP timeout in seconds
`NatUdpTimeout_u32` | `number` (uint32) | NAT UDP timeout in seconds
`UseDhcp_bool` | `boolean` | Using flag of DHCP function
`DhcpLeaseIPStart_ip` | `string` (IP address) | Specify the start point of the address band to be distributed to the client. (Example: 192.168.30.10)
`DhcpLeaseIPEnd_ip` | `string` (IP address) | Specify the end point of the address band to be distributed to the client. (Example: 192.168.30.200)
`DhcpSubnetMask_ip` | `string` (IP address) | Specify the subnet mask to be specified for the client. (Example: 255.255.255.0)
`DhcpExpireTimeSpan_u32` | `number` (uint32) | Specify the expiration date in second units for leasing an IP address to a client.
`DhcpGatewayAddress_ip` | `string` (IP address) | Specify the IP address of the default gateway to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify 0 or none, then the client will not be notified of the default gateway.
`DhcpDnsServerAddress_ip` | `string` (IP address) | Specify the IP address of the primary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
`DhcpDnsServerAddress2_ip` | `string` (IP address) | Specify the IP address of the secondary DNS Server to be notified to the client. You can specify a SecureNAT Virtual Host IP address for this when the SecureNAT Function's Virtual NAT Function has been enabled and is being used also. If you specify empty, then the client will not be notified of the DNS Server address.
`DhcpDomainName_str` | `string` (ASCII) | Specify the domain name to be notified to the client. If you specify none, then the client will not be notified of the domain name.
`SaveLog_bool` | `boolean` | Specify whether or not to save the Virtual DHCP Server operation in the Virtual Hub security log. Specify true to save it. This value is interlinked with the Virtual NAT Function log save setting.
`ApplyDhcpPushRoutes_bool` | `boolean` | The flag to enable the DhcpPushRoutes_str field.
`DhcpPushRoutes_str` | `string` (ASCII) | Specify the static routing table to push. Example: "192.168.5.0/255.255.255.0/192.168.4.254, 10.0.0.0/255.0.0.0/192.168.4.253" Split multiple entries (maximum: 64 entries) by comma or space characters. Each entry must be specified in the "IP network address/subnet mask/gateway IP address" format. This Virtual DHCP Server can push the classless static routes (RFC 3442) with DHCP reply messages to VPN clients. Whether or not a VPN client can recognize the classless static routes (RFC 3442) depends on the target VPN client software. SoftEther VPN Client and OpenVPN Client are supporting the classless static routes. On L2TP/IPsec and MS-SSTP protocols, the compatibility depends on the implementation of the client software. You can realize the split tunneling if you clear the default gateway field on the Virtual DHCP Server options. On the client side, L2TP/IPsec and MS-SSTP clients need to be configured not to set up the default gateway for the split tunneling usage. You can also push the classless static routes (RFC 3442) by your existing external DHCP server. In that case, disable the Virtual DHCP Server function on SecureNAT, and you need not to set up the classless routes on this API. See the RFC 3442 to understand the classless routes.

***
<a id="enumnat"></a>
## "EnumNAT" RPC API - Get Virtual NAT Function Session Table of SecureNAT Function
### Description
Get Virtual NAT Function Session Table of SecureNAT Function. Use this to get the table of TCP and UDP sessions currently communicating via the Virtual NAT (NAT table) in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumNAT",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "NatTable": [
      {
        "Id_u32": 0,
        "Protocol_u32": 0,
        "SrcIp_ip": "192.168.0.1",
        "SrcHost_str": "srchost",
        "SrcPort_u32": 0,
        "DestIp_ip": "192.168.0.1",
        "DestHost_str": "desthost",
        "DestPort_u32": 0,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "SendSize_u64": 0,
        "RecvSize_u64": 0,
        "TcpStatus_u32": 0
      },
      {
        "Id_u32": 0,
        "Protocol_u32": 0,
        "SrcIp_ip": "192.168.0.1",
        "SrcHost_str": "srchost",
        "SrcPort_u32": 0,
        "DestIp_ip": "192.168.0.1",
        "DestHost_str": "desthost",
        "DestPort_u32": 0,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "SendSize_u64": 0,
        "RecvSize_u64": 0,
        "TcpStatus_u32": 0
      },
      {
        "Id_u32": 0,
        "Protocol_u32": 0,
        "SrcIp_ip": "192.168.0.1",
        "SrcHost_str": "srchost",
        "SrcPort_u32": 0,
        "DestIp_ip": "192.168.0.1",
        "DestHost_str": "desthost",
        "DestPort_u32": 0,
        "CreatedTime_dt": "2020-08-01T12:24:36.123",
        "LastCommTime_dt": "2020-08-01T12:24:36.123",
        "SendSize_u64": 0,
        "RecvSize_u64": 0,
        "TcpStatus_u32": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual Hub Name
`NatTable` | `Array object` | NAT item
`Id_u32` | `number` (uint32) | ID
`Protocol_u32` | `number` (enum) | Protocol<BR>Values:<BR>`0`: TCP<BR>`1`: UDP<BR>`2`: DNS<BR>`3`: ICMP
`SrcIp_ip` | `string` (IP address) | Source IP address
`SrcHost_str` | `string` (ASCII) | Source host name
`SrcPort_u32` | `number` (uint32) | Source port number
`DestIp_ip` | `string` (IP address) | Destination IP address
`DestHost_str` | `string` (ASCII) | Destination host name
`DestPort_u32` | `number` (uint32) | Destination port number
`CreatedTime_dt` | `Date` | Connection time
`LastCommTime_dt` | `Date` | Last communication time
`SendSize_u64` | `number` (uint64) | Transmission size
`RecvSize_u64` | `number` (uint64) | Receive size
`TcpStatus_u32` | `number` (enum) | TCP state<BR>Values:<BR>`0`: Connecting<BR>`1`: Send the RST (Connection failure or disconnected)<BR>`2`: Connection complete<BR>`3`: Connection established<BR>`4`: Wait for socket disconnection

***
<a id="enumdhcp"></a>
## "EnumDHCP" RPC API - Get Virtual DHCP Server Function Lease Table of SecureNAT Function
### Description
Get Virtual DHCP Server Function Lease Table of SecureNAT Function. Use this to get the lease table of IP addresses, held by the Virtual DHCP Server, that are assigned to clients in cases when the Virtual NAT function is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumDHCP",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "DhcpTable": [
      {
        "Id_u32": 0,
        "LeasedTime_dt": "2020-08-01T12:24:36.123",
        "ExpireTime_dt": "2020-08-01T12:24:36.123",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "IpAddress_ip": "192.168.0.1",
        "Mask_u32": 0,
        "Hostname_str": "hostname"
      },
      {
        "Id_u32": 0,
        "LeasedTime_dt": "2020-08-01T12:24:36.123",
        "ExpireTime_dt": "2020-08-01T12:24:36.123",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "IpAddress_ip": "192.168.0.1",
        "Mask_u32": 0,
        "Hostname_str": "hostname"
      },
      {
        "Id_u32": 0,
        "LeasedTime_dt": "2020-08-01T12:24:36.123",
        "ExpireTime_dt": "2020-08-01T12:24:36.123",
        "MacAddress_bin": "SGVsbG8gV29ybGQ=",
        "IpAddress_ip": "192.168.0.1",
        "Mask_u32": 0,
        "Hostname_str": "hostname"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual Hub Name
`DhcpTable` | `Array object` | DHCP Item
`Id_u32` | `number` (uint32) | ID
`LeasedTime_dt` | `Date` | Lease time
`ExpireTime_dt` | `Date` | Expiration date
`MacAddress_bin` | `string` (Base64 binary) | MAC address
`IpAddress_ip` | `string` (IP address) | IP address
`Mask_u32` | `number` (uint32) | Subnet mask
`Hostname_str` | `string` (ASCII) | Host name

***
<a id="getsecurenatstatus"></a>
## "GetSecureNATStatus" RPC API - Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function)
### Description
Get the Operating Status of the Virtual NAT and DHCP Server Function (SecureNAT Function). Use this to get the operating status of the Virtual NAT and DHCP Server function (SecureNAT Function) when it is operating on the currently managed Virtual Hub. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetSecureNATStatus",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "NumTcpSessions_u32": 0,
    "NumUdpSessions_u32": 0,
    "NumIcmpSessions_u32": 0,
    "NumDnsSessions_u32": 0,
    "NumDhcpClients_u32": 0,
    "IsKernelMode_bool": false,
    "IsRawIpMode_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual Hub Name
`NumTcpSessions_u32` | `number` (uint32) | Number of TCP sessions
`NumUdpSessions_u32` | `number` (uint32) | Ntmber of UDP sessions
`NumIcmpSessions_u32` | `number` (uint32) | Nymber of ICMP sessions
`NumDnsSessions_u32` | `number` (uint32) | Number of DNS sessions
`NumDhcpClients_u32` | `number` (uint32) | Number of DHCP clients
`IsKernelMode_bool` | `boolean` | Whether the NAT is operating in the Kernel Mode
`IsRawIpMode_bool` | `boolean` | Whether the NAT is operating in the Raw IP Mode

***
<a id="enumethernet"></a>
## "EnumEthernet" RPC API - Get List of Network Adapters Usable as Local Bridge
### Description
Get List of Network Adapters Usable as Local Bridge. Use this to get a list of Ethernet devices (network adapters) that can be used as a bridge destination device as part of a Local Bridge connection. If possible, network connection name is displayed. You can use a device displayed here by using the AddLocalBridge API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumEthernet",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "EthList": [
      {
        "DeviceName_str": "devicename",
        "NetworkConnectionName_utf": "networkconnectionname"
      },
      {
        "DeviceName_str": "devicename",
        "NetworkConnectionName_utf": "networkconnectionname"
      },
      {
        "DeviceName_str": "devicename",
        "NetworkConnectionName_utf": "networkconnectionname"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`EthList` | `Array object` | Ethernet Network Adapters list
`DeviceName_str` | `string` (ASCII) | Device name
`NetworkConnectionName_utf` | `string` (UTF8) | Network connection name (description)

***
<a id="addlocalbridge"></a>
## "AddLocalBridge" RPC API - Create Local Bridge Connection
### Description
Create Local Bridge Connection. Use this to create a new Local Bridge connection on the VPN Server. By using a Local Bridge, you can configure a Layer 2 bridge connection between a Virtual Hub operating on this VPN server and a physical Ethernet Device (Network Adapter). You can create a tap device (virtual network interface) on the system and connect a bridge between Virtual Hubs (the tap device is only supported by Linux versions). It is possible to establish a bridge to an operating network adapter of your choice for the bridge destination Ethernet device (network adapter), but in high load environments, we recommend you prepare a network adapter dedicated to serve as a bridge. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddLocalBridge",
  "params": {
    "DeviceName_str": "devicename",
    "HubNameLB_str": "hubnamelb"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "DeviceName_str": "devicename",
    "HubNameLB_str": "hubnamelb",
    "Online_bool": false,
    "Active_bool": false,
    "TapMode_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`DeviceName_str` | `string` (ASCII) | Physical Ethernet device name
`HubNameLB_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`Active_bool` | `boolean` | Running flag
`TapMode_bool` | `boolean` | Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions).

***
<a id="deletelocalbridge"></a>
## "DeleteLocalBridge" RPC API - Delete Local Bridge Connection
### Description
Delete Local Bridge Connection. Use this to delete an existing Local Bridge connection. To get a list of current Local Bridge connections use the EnumLocalBridge API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteLocalBridge",
  "params": {
    "DeviceName_str": "devicename",
    "HubNameLB_str": "hubnamelb"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "DeviceName_str": "devicename",
    "HubNameLB_str": "hubnamelb",
    "Online_bool": false,
    "Active_bool": false,
    "TapMode_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`DeviceName_str` | `string` (ASCII) | Physical Ethernet device name
`HubNameLB_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`Active_bool` | `boolean` | Running flag
`TapMode_bool` | `boolean` | Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions).

***
<a id="enumlocalbridge"></a>
## "EnumLocalBridge" RPC API - Get List of Local Bridge Connection
### Description
Get List of Local Bridge Connection. Use this to get a list of the currently defined Local Bridge connections. You can get the Local Bridge connection Virtual Hub name and the bridge destination Ethernet device (network adapter) name or tap device name, as well as the operating status.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumLocalBridge",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "LocalBridgeList": [
      {
        "DeviceName_str": "devicename",
        "HubNameLB_str": "hubnamelb",
        "Online_bool": false,
        "Active_bool": false,
        "TapMode_bool": false
      },
      {
        "DeviceName_str": "devicename",
        "HubNameLB_str": "hubnamelb",
        "Online_bool": false,
        "Active_bool": false,
        "TapMode_bool": false
      },
      {
        "DeviceName_str": "devicename",
        "HubNameLB_str": "hubnamelb",
        "Online_bool": false,
        "Active_bool": false,
        "TapMode_bool": false
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`LocalBridgeList` | `Array object` | Local Bridge list
`DeviceName_str` | `string` (ASCII) | Physical Ethernet device name
`HubNameLB_str` | `string` (ASCII) | The Virtual Hub name
`Online_bool` | `boolean` | Online flag
`Active_bool` | `boolean` | Running flag
`TapMode_bool` | `boolean` | Specify true if you are using a tap device rather than a network adapter for the bridge destination (only supported for Linux versions).

***
<a id="getbridgesupport"></a>
## "GetBridgeSupport" RPC API - Get whether the localbridge function is supported on the current system
### Description
Get whether the localbridge function is supported on the current system.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetBridgeSupport",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IsBridgeSupportedOs_bool": false,
    "IsWinPcapNeeded_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IsBridgeSupportedOs_bool` | `boolean` | Whether the OS supports the Local Bridge function
`IsWinPcapNeeded_bool` | `boolean` | Whether WinPcap is necessary to install

***
<a id="rebootserver"></a>
## "RebootServer" RPC API - Reboot VPN Server Service
### Description
Reboot VPN Server Service. Use this to restart the VPN Server service. When you restart the VPN Server, all currently connected sessions and TCP connections will be disconnected and no new connections will be accepted until the restart process has completed. By using this API, only the VPN Server service program will be restarted and the physical computer that VPN Server is operating on does not restart. This management session will also be disconnected, so you will need to reconnect to continue management. Also, by specifying the "IntValue" parameter to "1", the contents of the configuration file (.config) held by the current VPN Server will be initialized. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "RebootServer",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="getcaps"></a>
## "GetCaps" RPC API - Get List of Server Functions / Capability
### Description
Get List of Server Functions / Capability. Use this get a list of functions and capability of the VPN Server currently connected and being managed. The function and capability of VPN Servers are different depending on the operating VPN server's edition and version. Using this API, you can find out the capability of the target VPN Server and report it.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetCaps",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "CapsList": [
      {
        "CapsName_str": "capsname",
        "CapsValue_u32": 0,
        "CapsDescrption_utf": "capsdescrption"
      },
      {
        "CapsName_str": "capsname",
        "CapsValue_u32": 0,
        "CapsDescrption_utf": "capsdescrption"
      },
      {
        "CapsName_str": "capsname",
        "CapsValue_u32": 0,
        "CapsDescrption_utf": "capsdescrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`CapsList` | `Array object` | Caps list of the VPN Server
`CapsName_str` | `string` (ASCII) | Name
`CapsValue_u32` | `number` (uint32) | Value
`CapsDescrption_utf` | `string` (UTF8) | Descrption

***
<a id="getconfig"></a>
## "GetConfig" RPC API - Get the current configuration of the VPN Server
### Description
Get the current configuration of the VPN Server. Use this to get a text file (.config file) that contains the current configuration contents of the VPN server. You can get the status on the VPN Server at the instant this API is executed. You can edit the configuration file by using a regular text editor. To write an edited configuration to the VPN Server, use the SetConfig API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetConfig",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "FileName_str": "filename",
    "FileData_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`FileName_str` | `string` (ASCII) | File name (valid only for returning from the server)
`FileData_bin` | `string` (Base64 binary) | File data

***
<a id="setconfig"></a>
## "SetConfig" RPC API - Write Configuration File to VPN Server
### Description
Write Configuration File to VPN Server. Use this to write the configuration file to the VPN Server. By executing this API, the contents of the specified configuration file will be applied to the VPN Server and the VPN Server program will automatically restart and upon restart, operate according to the new configuration contents. Because it is difficult for an administrator to write all the contents of a configuration file, we recommend you use the GetConfig API to get the current contents of the VPN Server configuration and save it to file. You can then edit these contents in a regular text editor and then use the SetConfig API to rewrite the contents to the VPN Server. This API is for people with a detailed knowledge of the VPN Server and if an incorrectly configured configuration file is written to the VPN Server, it not only could cause errors, it could also result in the lost of the current setting data. Take special care when carrying out this action. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetConfig",
  "params": {
    "FileData_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "FileName_str": "filename",
    "FileData_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`FileName_str` | `string` (ASCII) | File name (valid only for returning from the server)
`FileData_bin` | `string` (Base64 binary) | File data

***
<a id="getdefaulthubadminoptions"></a>
## "GetDefaultHubAdminOptions" RPC API - Get Virtual Hub Administration Option default values
### Description
Get Virtual Hub Administration Option default values.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetDefaultHubAdminOptions",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual HUB name
`AdminOptionList` | `Array object` | List data
`Name_str` | `string` (ASCII) | Name
`Value_u32` | `number` (uint32) | Data
`Descrption_utf` | `string` (UTF8) | Descrption

***
<a id="gethubadminoptions"></a>
## "GetHubAdminOptions" RPC API - Get List of Virtual Hub Administration Options
### Description
Get List of Virtual Hub Administration Options. Use this to get a list of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubAdminOptions",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual HUB name
`AdminOptionList` | `Array object` | List data
`Name_str` | `string` (ASCII) | Name
`Value_u32` | `number` (uint32) | Data
`Descrption_utf` | `string` (UTF8) | Descrption

***
<a id="sethubadminoptions"></a>
## "SetHubAdminOptions" RPC API - Set Values of Virtual Hub Administration Options
### Description
Set Values of Virtual Hub Administration Options. Use this to change the values of Virtual Hub administration options that are set on the currently managed Virtual Hub. The purpose of the Virtual Hub administration options is for the VPN Server Administrator to set limits for the setting ranges when the administration of the Virtual Hub is to be trusted to each Virtual Hub administrator. Only an administrator with administration privileges for this entire VPN Server is able to add, edit and delete the Virtual Hub administration options. The Virtual Hub administrators are unable to make changes to the administration options, however they are able to view them. There is an exception however. If allow_hub_admin_change_option is set to "1", even Virtual Hub administrators are able to edit the administration options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubAdminOptions",
  "params": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual HUB name
`AdminOptionList` | `Array object` | List data
`Name_str` | `string` (ASCII) | Name
`Value_u32` | `number` (uint32) | Data
`Descrption_utf` | `string` (UTF8) | Descrption

***
<a id="gethubextoptions"></a>
## "GetHubExtOptions" RPC API - Get List of Virtual Hub Extended Options
### Description
Get List of Virtual Hub Extended Options. Use this to get a Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubExtOptions",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual HUB name
`AdminOptionList` | `Array object` | List data
`Name_str` | `string` (ASCII) | Name
`Value_u32` | `number` (uint32) | Data
`Descrption_utf` | `string` (UTF8) | Descrption

***
<a id="sethubextoptions"></a>
## "SetHubExtOptions" RPC API - Set a Value of Virtual Hub Extended Options
### Description
Set a Value of Virtual Hub Extended Options. Use this to set a value in the Virtual Hub Extended Options List that is set on the currently managed Virtual Hub. Virtual Hub Extended Option enables you to configure more detail settings of the Virtual Hub. By default, both VPN Server's global administrators and individual Virtual Hub's administrators can modify the Virtual Hub Extended Options. However, if the deny_hub_admin_change_ext_option is set to 1 on the Virtual Hub Admin Options, the individual Virtual Hub's administrators cannot modify the Virtual Hub Extended Options. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster member.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubExtOptions",
  "params": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "AdminOptionList": [
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      },
      {
        "Name_str": "name",
        "Value_u32": 0,
        "Descrption_utf": "descrption"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | Virtual HUB name
`AdminOptionList` | `Array object` | List data
`Name_str` | `string` (ASCII) | Name
`Value_u32` | `number` (uint32) | Data
`Descrption_utf` | `string` (UTF8) | Descrption

***
<a id="addl3switch"></a>
## "AddL3Switch" RPC API - Define New Virtual Layer 3 Switch
### Description
Define New Virtual Layer 3 Switch. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddL3Switch",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Layer-3 Switch name

***
<a id="dell3switch"></a>
## "DelL3Switch" RPC API - Delete Virtual Layer 3 Switch
### Description
Delete Virtual Layer 3 Switch. Use this to delete an existing Virtual Layer 3 Switch that is defined on the VPN Server. When the specified Virtual Layer 3 Switch is operating, it will be automatically deleted after operation stops. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DelL3Switch",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Layer-3 Switch name

***
<a id="enuml3switch"></a>
## "EnumL3Switch" RPC API - Get List of Virtual Layer 3 Switches
### Description
Get List of Virtual Layer 3 Switches. Use this to define a new Virtual Layer 3 Switch on the VPN Server. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumL3Switch",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "L3SWList": [
      {
        "Name_str": "name",
        "NumInterfaces_u32": 0,
        "NumTables_u32": 0,
        "Active_bool": false,
        "Online_bool": false
      },
      {
        "Name_str": "name",
        "NumInterfaces_u32": 0,
        "NumTables_u32": 0,
        "Active_bool": false,
        "Online_bool": false
      },
      {
        "Name_str": "name",
        "NumInterfaces_u32": 0,
        "NumTables_u32": 0,
        "Active_bool": false,
        "Online_bool": false
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`L3SWList` | `Array object` | Layer-3 switch list
`Name_str` | `string` (ASCII) | Name of the layer-3 switch
`NumInterfaces_u32` | `number` (uint32) | Number of layer-3 switch virtual interfaces
`NumTables_u32` | `number` (uint32) | Number of routing tables
`Active_bool` | `boolean` | Activated flag
`Online_bool` | `boolean` | Online flag

***
<a id="startl3switch"></a>
## "StartL3Switch" RPC API - Start Virtual Layer 3 Switch Operation
### Description
Start Virtual Layer 3 Switch Operation. Use this to start the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently stopped. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. [Explanation on Virtual Layer 3 Switch Function] You can define Virtual Layer 3 Switches between multiple Virtual Hubs operating on this VPN Server and configure routing between different IP networks. [Caution about the Virtual Layer 3 Switch Function] The Virtual Layer 3 Switch functions are provided for network administrators and other people who know a lot about networks and IP routing. If you are using the regular VPN functions, you do not need to use the Virtual Layer 3 Switch functions. If the Virtual Layer 3 Switch functions are to be used, the person who configures them must have sufficient knowledge of IP routing and be perfectly capable of not impacting the network.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "StartL3Switch",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Layer-3 Switch name

***
<a id="stopl3switch"></a>
## "StopL3Switch" RPC API - Stop Virtual Layer 3 Switch Operation
### Description
Stop Virtual Layer 3 Switch Operation. Use this to stop the operation of an existing Virtual Layer 3 Switch defined on the VPN Server whose operation is currently operating. To get a list of existing Virtual Layer 3 Switches, use the EnumL3Switch API. To call this API, you must have VPN Server administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "StopL3Switch",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Layer-3 Switch name

***
<a id="addl3if"></a>
## "AddL3If" RPC API - Add Virtual Interface to Virtual Layer 3 Switch
### Description
Add Virtual Interface to Virtual Layer 3 Switch. Use this to add to a specified Virtual Layer 3 Switch, a virtual interface that connects to a Virtual Hub operating on the same VPN Server. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. You must define the IP network space that the virtual interface belongs to and the IP address of the interface itself. Also, you must specify the name of the Virtual Hub that the interface will connect to. You can specify a Virtual Hub that currently doesn't exist for the Virtual Hub name. The virtual interface must have one IP address in the Virtual Hub. You also must specify the subnet mask of an IP network that the IP address belongs to. Routing via the Virtual Layer 3 Switches of IP spaces of multiple virtual Hubs operates based on the IP address is specified here. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddL3If",
  "params": {
    "Name_str": "name",
    "HubName_str": "hubname",
    "IpAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "HubName_str": "hubname",
    "IpAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | L3 switch name
`HubName_str` | `string` (ASCII) | Virtual HUB name
`IpAddress_ip` | `string` (IP address) | IP address
`SubnetMask_ip` | `string` (IP address) | Subnet mask

***
<a id="dell3if"></a>
## "DelL3If" RPC API - Delete Virtual Interface of Virtual Layer 3 Switch
### Description
Delete Virtual Interface of Virtual Layer 3 Switch. Use this to delete a virtual interface already defined in the specified Virtual Layer 3 Switch. You can get a list of the virtual interfaces currently defined, by using the EnumL3If API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DelL3If",
  "params": {
    "Name_str": "name",
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "HubName_str": "hubname",
    "IpAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | L3 switch name
`HubName_str` | `string` (ASCII) | Virtual HUB name
`IpAddress_ip` | `string` (IP address) | IP address
`SubnetMask_ip` | `string` (IP address) | Subnet mask

***
<a id="enuml3if"></a>
## "EnumL3If" RPC API - Get List of Interfaces Registered on the Virtual Layer 3 Switch
### Description
Get List of Interfaces Registered on the Virtual Layer 3 Switch. Use this to get a list of virtual interfaces when virtual interfaces have been defined on a specified Virtual Layer 3 Switch. You can define multiple virtual interfaces and routing tables for a single Virtual Layer 3 Switch. A virtual interface is associated to a virtual Hub and operates as a single IP host on the Virtual Hub when that Virtual Hub is operating. When multiple virtual interfaces that respectively belong to a different IP network of a different Virtual Hub are defined, IP routing will be automatically performed between these interfaces. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumL3If",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "L3IFList": [
      {
        "Name_str": "name",
        "HubName_str": "hubname",
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Name_str": "name",
        "HubName_str": "hubname",
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Name_str": "name",
        "HubName_str": "hubname",
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | Layer-3 switch name
`L3IFList` | `Array object` | Layer-3 interface list
`Name_str` | `string` (ASCII) | L3 switch name
`HubName_str` | `string` (ASCII) | Virtual HUB name
`IpAddress_ip` | `string` (IP address) | IP address
`SubnetMask_ip` | `string` (IP address) | Subnet mask

***
<a id="addl3table"></a>
## "AddL3Table" RPC API - Add Routing Table Entry for Virtual Layer 3 Switch
### Description
Add Routing Table Entry for Virtual Layer 3 Switch. Here you can add a new routing table entry to the routing table of the specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference the routing table and execute routing. You must specify the contents of the routing table entry to be added to the Virtual Layer 3 Switch. You must specify any IP address that belongs to the same IP network in the virtual interface of this Virtual Layer 3 Switch as the gateway address. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddL3Table",
  "params": {
    "Name_str": "name",
    "NetworkAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255",
    "GatewayAddress_ip": "192.168.0.1",
    "Metric_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "NetworkAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255",
    "GatewayAddress_ip": "192.168.0.1",
    "Metric_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | L3 switch name
`NetworkAddress_ip` | `string` (IP address) | Network address
`SubnetMask_ip` | `string` (IP address) | Subnet mask
`GatewayAddress_ip` | `string` (IP address) | Gateway address
`Metric_u32` | `number` (uint32) | Metric

***
<a id="dell3table"></a>
## "DelL3Table" RPC API - Delete Routing Table Entry of Virtual Layer 3 Switch
### Description
Delete Routing Table Entry of Virtual Layer 3 Switch. Use this to delete a routing table entry that is defined in the specified Virtual Layer 3 Switch. You can get a list of the already defined routing table entries by using the EnumL3Table API. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge. To execute this API, the target Virtual Layer 3 Switch must be stopped. If it is not stopped, first use the StopL3Switch API to stop it and then execute this API.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DelL3Table",
  "params": {
    "Name_str": "name",
    "NetworkAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255",
    "GatewayAddress_ip": "192.168.0.1",
    "Metric_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "NetworkAddress_ip": "192.168.0.1",
    "SubnetMask_ip": "255.255.255.255",
    "GatewayAddress_ip": "192.168.0.1",
    "Metric_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | L3 switch name
`NetworkAddress_ip` | `string` (IP address) | Network address
`SubnetMask_ip` | `string` (IP address) | Subnet mask
`GatewayAddress_ip` | `string` (IP address) | Gateway address
`Metric_u32` | `number` (uint32) | Metric

***
<a id="enuml3table"></a>
## "EnumL3Table" RPC API - Get List of Routing Tables of Virtual Layer 3 Switch
### Description
Get List of Routing Tables of Virtual Layer 3 Switch. Use this to get a list of routing tables when routing tables have been defined on a specified Virtual Layer 3 Switch. If the destination IP address of the IP packet does not belong to any IP network that belongs to a virtual interface, the IP routing engine of the Virtual Layer 3 Switch will reference this routing table and execute routing. To call this API, you must have VPN Server administrator privileges. Also, this API does not operate on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumL3Table",
  "params": {
    "Name_str": "name"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Name_str": "name",
    "L3Table": [
      {
        "Name_str": "name",
        "NetworkAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255",
        "GatewayAddress_ip": "192.168.0.1",
        "Metric_u32": 0
      },
      {
        "Name_str": "name",
        "NetworkAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255",
        "GatewayAddress_ip": "192.168.0.1",
        "Metric_u32": 0
      },
      {
        "Name_str": "name",
        "NetworkAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255",
        "GatewayAddress_ip": "192.168.0.1",
        "Metric_u32": 0
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Name_str` | `string` (ASCII) | L3 switch name
`L3Table` | `Array object` | Routing table item list
`Name_str` | `string` (ASCII) | L3 switch name
`NetworkAddress_ip` | `string` (IP address) | Network address
`SubnetMask_ip` | `string` (IP address) | Subnet mask
`GatewayAddress_ip` | `string` (IP address) | Gateway address
`Metric_u32` | `number` (uint32) | Metric

***
<a id="enumcrl"></a>
## "EnumCrl" RPC API - Get List of Certificates Revocation List
### Description
Get List of Certificates Revocation List. Use this to get a Certificates Revocation List that is set on the currently managed Virtual Hub. By registering certificates in the Certificates Revocation List, the clients who provide these certificates will be unable to connect to this Virtual Hub using certificate authentication mode. Normally with this function, in cases where the security of a private key has been compromised or where a person holding a certificate has been stripped of their privileges, by registering that certificate as invalid on the Virtual Hub, it is possible to deny user authentication when that certificate is used by a client to connect to the Virtual Hub. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumCrl",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "CRLList": [
      {
        "Key_u32": 0,
        "CrlInfo_utf": "crlinfo"
      },
      {
        "Key_u32": 0,
        "CrlInfo_utf": "crlinfo"
      },
      {
        "Key_u32": 0,
        "CrlInfo_utf": "crlinfo"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`CRLList` | `Array object` | CRL list
`Key_u32` | `number` (uint32) | Key ID
`CrlInfo_utf` | `string` (UTF8) | The contents of the CRL item

***
<a id="addcrl"></a>
## "AddCrl" RPC API - Add a Revoked Certificate
### Description
Add a Revoked Certificate. Use this to add a new revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddCrl",
  "params": {
    "HubName_str": "hubname",
    "CommonName_utf": "commonname",
    "Organization_utf": "organization",
    "Unit_utf": "unit",
    "Country_utf": "country",
    "State_utf": "state",
    "Local_utf": "local",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "DigestMD5_bin": "SGVsbG8gV29ybGQ=",
    "DigestSHA1_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0,
    "CommonName_utf": "commonname",
    "Organization_utf": "organization",
    "Unit_utf": "unit",
    "Country_utf": "country",
    "State_utf": "state",
    "Local_utf": "local",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "DigestMD5_bin": "SGVsbG8gV29ybGQ=",
    "DigestSHA1_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID
`CommonName_utf` | `string` (UTF8) | CN, optional
`Organization_utf` | `string` (UTF8) | O, optional
`Unit_utf` | `string` (UTF8) | OU, optional
`Country_utf` | `string` (UTF8) | C, optional
`State_utf` | `string` (UTF8) | ST, optional
`Local_utf` | `string` (UTF8) | L, optional
`Serial_bin` | `string` (Base64 binary) | Serial, optional
`DigestMD5_bin` | `string` (Base64 binary) | MD5 Digest, optional
`DigestSHA1_bin` | `string` (Base64 binary) | SHA1 Digest, optional

***
<a id="delcrl"></a>
## "DelCrl" RPC API - Delete a Revoked Certificate
### Description
Delete a Revoked Certificate. Use this to specify and delete a revoked certificate definition from the certificate revocation list that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DelCrl",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0,
    "CommonName_utf": "commonname",
    "Organization_utf": "organization",
    "Unit_utf": "unit",
    "Country_utf": "country",
    "State_utf": "state",
    "Local_utf": "local",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "DigestMD5_bin": "SGVsbG8gV29ybGQ=",
    "DigestSHA1_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID
`CommonName_utf` | `string` (UTF8) | CN, optional
`Organization_utf` | `string` (UTF8) | O, optional
`Unit_utf` | `string` (UTF8) | OU, optional
`Country_utf` | `string` (UTF8) | C, optional
`State_utf` | `string` (UTF8) | ST, optional
`Local_utf` | `string` (UTF8) | L, optional
`Serial_bin` | `string` (Base64 binary) | Serial, optional
`DigestMD5_bin` | `string` (Base64 binary) | MD5 Digest, optional
`DigestSHA1_bin` | `string` (Base64 binary) | SHA1 Digest, optional

***
<a id="getcrl"></a>
## "GetCrl" RPC API - Get a Revoked Certificate
### Description
Get a Revoked Certificate. Use this to specify and get the contents of a revoked certificate definition from the Certificates Revocation List that is set on the currently managed Virtual Hub. To get the list of currently registered revoked certificate definitions, use the EnumCrl API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetCrl",
  "params": {
    "HubName_str": "hubname",
    "Key_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0,
    "CommonName_utf": "commonname",
    "Organization_utf": "organization",
    "Unit_utf": "unit",
    "Country_utf": "country",
    "State_utf": "state",
    "Local_utf": "local",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "DigestMD5_bin": "SGVsbG8gV29ybGQ=",
    "DigestSHA1_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID
`CommonName_utf` | `string` (UTF8) | CN, optional
`Organization_utf` | `string` (UTF8) | O, optional
`Unit_utf` | `string` (UTF8) | OU, optional
`Country_utf` | `string` (UTF8) | C, optional
`State_utf` | `string` (UTF8) | ST, optional
`Local_utf` | `string` (UTF8) | L, optional
`Serial_bin` | `string` (Base64 binary) | Serial, optional
`DigestMD5_bin` | `string` (Base64 binary) | MD5 Digest, optional
`DigestSHA1_bin` | `string` (Base64 binary) | SHA1 Digest, optional

***
<a id="setcrl"></a>
## "SetCrl" RPC API - Change Existing CRL (Certificate Revocation List) Entry
### Description
Change Existing CRL (Certificate Revocation List) Entry. Use this to alter an existing revoked certificate definition in the Certificate Revocation List that is set on the currently managed Virtual Hub. Specify the contents to be registered in the Certificate Revocation List by using the parameters of this API. When a user connects to a Virtual Hub in certificate authentication mode and that certificate matches 1 or more of the contents registered in the certificates revocation list, the user is denied connection. A certificate that matches all the conditions that are defined by the parameters specified by this API will be judged as invalid. The items that can be set are as follows: Name (CN), Organization (O), Organization Unit (OU), Country (C), State (ST), Locale (L), Serial Number (hexadecimal), MD5 Digest Value (hexadecimal, 128 bit), and SHA-1 Digest Value (hexadecimal, 160 bit). For the specification of a digest value (hash value) a certificate is optionally specified depending on the circumstances. Normally when a MD5 or SHA-1 digest value is input, it is not necessary to input the other items. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetCrl",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Key_u32": 0,
    "CommonName_utf": "commonname",
    "Organization_utf": "organization",
    "Unit_utf": "unit",
    "Country_utf": "country",
    "State_utf": "state",
    "Local_utf": "local",
    "Serial_bin": "SGVsbG8gV29ybGQ=",
    "DigestMD5_bin": "SGVsbG8gV29ybGQ=",
    "DigestSHA1_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Key_u32` | `number` (uint32) | Key ID
`CommonName_utf` | `string` (UTF8) | CN, optional
`Organization_utf` | `string` (UTF8) | O, optional
`Unit_utf` | `string` (UTF8) | OU, optional
`Country_utf` | `string` (UTF8) | C, optional
`State_utf` | `string` (UTF8) | ST, optional
`Local_utf` | `string` (UTF8) | L, optional
`Serial_bin` | `string` (Base64 binary) | Serial, optional
`DigestMD5_bin` | `string` (Base64 binary) | MD5 Digest, optional
`DigestSHA1_bin` | `string` (Base64 binary) | SHA1 Digest, optional

***
<a id="setaclist"></a>
## "SetAcList" RPC API - Add Rule to Source IP Address Limit List
### Description
Add Rule to Source IP Address Limit List. Use this to add a new rule to the Source IP Address Limit List that is set on the currently managed Virtual Hub. The items set here will be used to decide whether to allow or deny connection from a VPN Client when this client attempts connection to the Virtual Hub. You can specify a client IP address, or IP address or mask to match the rule as the contents of the rule item. By specifying an IP address only, there will only be one specified computer that will match the rule, but by specifying an IP net mask address or subnet mask address, all the computers in the range of that subnet will match the rule. You can specify the priority for the rule. You can specify an integer of 1 or greater for the priority and the smaller the number, the higher the priority. To get a list of the currently registered Source IP Address Limit List, use the GetAcList API. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetAcList",
  "params": {
    "HubName_str": "hubname",
    "ACList": [
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      }
    ]
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "ACList": [
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`ACList` | `Array object` | Source IP Address Limit List
`Id_u32` | `number` (uint32) | ID
`Priority_u32` | `number` (uint32) | Priority
`Deny_bool` | `boolean` | Deny access
`Masked_bool` | `boolean` | Set true if you want to specify the SubnetMask_ip item.
`IpAddress_ip` | `string` (IP address) | IP address
`SubnetMask_ip` | `string` (IP address) | Subnet mask, valid only if Masked_bool == true

***
<a id="getaclist"></a>
## "GetAcList" RPC API - Get List of Rule Items of Source IP Address Limit List
### Description
Get List of Rule Items of Source IP Address Limit List. Use this to get a list of Source IP Address Limit List rules that is set on the currently managed Virtual Hub. You can allow or deny VPN connections to this Virtual Hub according to the client computer's source IP address. You can define multiple rules and set a priority for each rule. The search proceeds from the rule with the highest order or priority and based on the action of the rule that the IP address first matches, the connection from the client is either allowed or denied. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetAcList",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "ACList": [
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      },
      {
        "Id_u32": 0,
        "Priority_u32": 0,
        "Deny_bool": false,
        "Masked_bool": false,
        "IpAddress_ip": "192.168.0.1",
        "SubnetMask_ip": "255.255.255.255"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`ACList` | `Array object` | Source IP Address Limit List
`Id_u32` | `number` (uint32) | ID
`Priority_u32` | `number` (uint32) | Priority
`Deny_bool` | `boolean` | Deny access
`Masked_bool` | `boolean` | Set true if you want to specify the SubnetMask_ip item.
`IpAddress_ip` | `string` (IP address) | IP address
`SubnetMask_ip` | `string` (IP address) | Subnet mask, valid only if Masked_bool == true

***
<a id="enumlogfile"></a>
## "EnumLogFile" RPC API - Get List of Log Files
### Description
Get List of Log Files. Use this to display a list of log files outputted by the VPN Server that have been saved on the VPN Server computer. By specifying a log file file name displayed here and calling it using the ReadLogFile API you can download the contents of the log file. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumLogFile",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "LogFiles": [
      {
        "ServerName_str": "servername",
        "FilePath_str": "filepath",
        "FileSize_u32": 0,
        "UpdatedTime_dt": "2020-08-01T12:24:36.123"
      },
      {
        "ServerName_str": "servername",
        "FilePath_str": "filepath",
        "FileSize_u32": 0,
        "UpdatedTime_dt": "2020-08-01T12:24:36.123"
      },
      {
        "ServerName_str": "servername",
        "FilePath_str": "filepath",
        "FileSize_u32": 0,
        "UpdatedTime_dt": "2020-08-01T12:24:36.123"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`LogFiles` | `Array object` | Log file list
`ServerName_str` | `string` (ASCII) | Server name
`FilePath_str` | `string` (ASCII) | File path
`FileSize_u32` | `number` (uint32) | File size
`UpdatedTime_dt` | `Date` | Last write date

***
<a id="readlogfile"></a>
## "ReadLogFile" RPC API - Download a part of Log File
### Description
Download a part of Log File. Use this to download the log file that is saved on the VPN Server computer. To download the log file first get the list of log files using the EnumLogFile API and then download the log file using the ReadLogFile API. If you are connected to the VPN Server in server admin mode, you can display or download the packet logs and security logs of all Virtual Hubs and the server log of the VPN Server. When connected in Virtual Hub Admin Mode, you are able to view or download only the packet log and security log of the Virtual Hub that is the target of management.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "ReadLogFile",
  "params": {
    "FilePath_str": "filepath"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerName_str": "servername",
    "FilePath_str": "filepath",
    "Offset_u32": 0,
    "Buffer_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerName_str` | `string` (ASCII) | Server name
`FilePath_str` | `string` (ASCII) | File Path
`Offset_u32` | `number` (uint32) | Offset to download. You have to call the ReadLogFile API multiple times to download the entire log file with requesting a part of the file by specifying the Offset_u32 field.
`Buffer_bin` | `string` (Base64 binary) | Received buffer

***
<a id="setsyslog"></a>
## "SetSysLog" RPC API - Set syslog Send Function
### Description
Set syslog Send Function. Use this to set the usage of syslog send function and which syslog server to use.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetSysLog",
  "params": {
    "SaveType_u32": 0,
    "Hostname_str": "hostname",
    "Port_u32": 0
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "SaveType_u32": 0,
    "Hostname_str": "hostname",
    "Port_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`SaveType_u32` | `number` (enum) | The behavior of the syslog function<BR>Values:<BR>`0`: Do not use syslog<BR>`1`: Only server log<BR>`2`: Server and Virtual HUB security log<BR>`3`: Server, Virtual HUB security, and packet log
`Hostname_str` | `string` (ASCII) | Specify the host name or IP address of the syslog server
`Port_u32` | `number` (uint32) | Specify the port number of the syslog server

***
<a id="getsyslog"></a>
## "GetSysLog" RPC API - Get syslog Send Function
### Description
Get syslog Send Function. This allows you to get the current setting contents of the syslog send function. You can get the usage setting of the syslog function and the host name and port number of the syslog server to use.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetSysLog",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "SaveType_u32": 0,
    "Hostname_str": "hostname",
    "Port_u32": 0
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`SaveType_u32` | `number` (enum) | The behavior of the syslog function<BR>Values:<BR>`0`: Do not use syslog<BR>`1`: Only server log<BR>`2`: Server and Virtual HUB security log<BR>`3`: Server, Virtual HUB security, and packet log
`Hostname_str` | `string` (ASCII) | Specify the host name or IP address of the syslog server
`Port_u32` | `number` (uint32) | Specify the port number of the syslog server

***
<a id="sethubmsg"></a>
## "SetHubMsg" RPC API - Set Today's Message of Virtual Hub
### Description
Set Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetHubMsg",
  "params": {
    "HubName_str": "hubname",
    "Msg_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Msg_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Msg_bin` | `string` (Base64 binary) | Message (Unicode strings acceptable)

***
<a id="gethubmsg"></a>
## "GetHubMsg" RPC API - Get Today's Message of Virtual Hub
### Description
Get Today's Message of Virtual Hub. The message will be displayed on VPN Client UI when a user will establish a connection to the Virtual Hub.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetHubMsg",
  "params": {
    "HubName_str": "hubname"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Msg_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Msg_bin` | `string` (Base64 binary) | Message (Unicode strings acceptable)

***
<a id="crash"></a>
## "Crash" RPC API - Raise a vital error on the VPN Server / Bridge to terminate the process forcefully
### Description
Raise a vital error on the VPN Server / Bridge to terminate the process forcefully. This API will raise a fatal error (memory access violation) on the VPN Server / Bridge running process in order to crash the process. As the result, VPN Server / Bridge will be terminated and restarted if it is running as a service mode. If the VPN Server is running as a user mode, the process will not automatically restarted. This API is for a situation when the VPN Server / Bridge is under a non-recoverable error or the process is in an infinite loop. This API will disconnect all VPN Sessions on the VPN Server / Bridge. All unsaved settings in the memory of VPN Server / Bridge will be lost. Before run this API, call the Flush API to try to save volatile data to the configuration file. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "Crash",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="getadminmsg"></a>
## "GetAdminMsg" RPC API - Get the message for administrators
### Description
Get the message for administrators.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetAdminMsg",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "HubName_str": "hubname",
    "Msg_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`HubName_str` | `string` (ASCII) | The Virtual Hub name
`Msg_bin` | `string` (Base64 binary) | Message (Unicode strings acceptable)

***
<a id="flush"></a>
## "Flush" RPC API - Save All Volatile Data of VPN Server / Bridge to the Configuration File
### Description
Save All Volatile Data of VPN Server / Bridge to the Configuration File. The number of configuration file bytes will be returned as the "IntValue" parameter. Normally, the VPN Server / VPN Bridge retains the volatile configuration data in memory. It is flushed to the disk as vpn_server.config or vpn_bridge.config periodically. The period is 300 seconds (5 minutes) by default. (The period can be altered by modifying the AutoSaveConfigSpan item in the configuration file.) The data will be saved on the timing of shutting down normally of the VPN Server / Bridge. Execute the Flush API to make the VPN Server / Bridge save the settings to the file immediately. The setting data will be stored on the disk drive of the server computer. Use the Flush API in a situation that you do not have an enough time to shut down the server process normally. To call this API, you must have VPN Server administrator privileges. To execute this API, you must have VPN Server / VPN Bridge administrator privileges.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "Flush",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="setipsecservices"></a>
## "SetIPsecServices" RPC API - Enable or Disable IPsec VPN Server Function
### Description
Enable or Disable IPsec VPN Server Function. Enable or Disable IPsec VPN Server Function on the VPN Server. If you enable this function, Virtual Hubs on the VPN Server will be able to accept Remote-Access VPN connections from L2TP-compatible PCs, Mac OS X and Smartphones, and also can accept EtherIP Site-to-Site VPN Connection. VPN Connections from Smartphones suchlike iPhone, iPad and Android, and also from native VPN Clients on Mac OS X and Windows can be accepted. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetIPsecServices",
  "params": {
    "L2TP_Raw_bool": false,
    "L2TP_IPsec_bool": false,
    "EtherIP_IPsec_bool": false,
    "IPsec_Secret_str": "ipsec_secret",
    "L2TP_DefaultHub_str": "l2tp_defaulthub"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "L2TP_Raw_bool": false,
    "L2TP_IPsec_bool": false,
    "EtherIP_IPsec_bool": false,
    "IPsec_Secret_str": "ipsec_secret",
    "L2TP_DefaultHub_str": "l2tp_defaulthub"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`L2TP_Raw_bool` | `boolean` | Enable or Disable the L2TP Server Function (Raw L2TP with No Encryptions). To accept special VPN clients, enable this option.
`L2TP_IPsec_bool` | `boolean` | Enable or Disable the L2TP over IPsec Server Function. To accept VPN connections from iPhone, iPad, Android, Windows or Mac OS X, enable this option.
`EtherIP_IPsec_bool` | `boolean` | Enable or Disable the EtherIP / L2TPv3 over IPsec Server Function (for site-to-site VPN Server function). Router Products which are compatible with EtherIP over IPsec can connect to Virtual Hubs on the VPN Server and establish Layer-2 (Ethernet) Bridging.
`IPsec_Secret_str` | `string` (ASCII) | Specify the IPsec Pre-Shared Key. An IPsec Pre-Shared Key is also called as "PSK" or "secret". Specify it equal or less than 8 letters, and distribute it to every users who will connect to the VPN Server. Please note: Google Android 4.0 has a bug which a Pre-Shared Key with 10 or more letters causes a unexpected behavior. For that reason, the letters of a Pre-Shared Key should be 9 or less characters.
`L2TP_DefaultHub_str` | `string` (ASCII) | Specify the default Virtual HUB in a case of omitting the name of HUB on the Username. Users should specify their username such as "Username@Target Virtual HUB Name" to connect this L2TP Server. If the designation of the Virtual Hub is omitted, the above HUB will be used as the target.

***
<a id="getipsecservices"></a>
## "GetIPsecServices" RPC API - Get the Current IPsec VPN Server Settings
### Description
Get the Current IPsec VPN Server Settings. Get and view the current IPsec VPN Server settings on the VPN Server. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetIPsecServices",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "L2TP_Raw_bool": false,
    "L2TP_IPsec_bool": false,
    "EtherIP_IPsec_bool": false,
    "IPsec_Secret_str": "ipsec_secret",
    "L2TP_DefaultHub_str": "l2tp_defaulthub"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`L2TP_Raw_bool` | `boolean` | Enable or Disable the L2TP Server Function (Raw L2TP with No Encryptions). To accept special VPN clients, enable this option.
`L2TP_IPsec_bool` | `boolean` | Enable or Disable the L2TP over IPsec Server Function. To accept VPN connections from iPhone, iPad, Android, Windows or Mac OS X, enable this option.
`EtherIP_IPsec_bool` | `boolean` | Enable or Disable the EtherIP / L2TPv3 over IPsec Server Function (for site-to-site VPN Server function). Router Products which are compatible with EtherIP over IPsec can connect to Virtual Hubs on the VPN Server and establish Layer-2 (Ethernet) Bridging.
`IPsec_Secret_str` | `string` (ASCII) | Specify the IPsec Pre-Shared Key. An IPsec Pre-Shared Key is also called as "PSK" or "secret". Specify it equal or less than 8 letters, and distribute it to every users who will connect to the VPN Server. Please note: Google Android 4.0 has a bug which a Pre-Shared Key with 10 or more letters causes a unexpected behavior. For that reason, the letters of a Pre-Shared Key should be 9 or less characters.
`L2TP_DefaultHub_str` | `string` (ASCII) | Specify the default Virtual HUB in a case of omitting the name of HUB on the Username. Users should specify their username such as "Username@Target Virtual HUB Name" to connect this L2TP Server. If the designation of the Virtual Hub is omitted, the above HUB will be used as the target.

***
<a id="addetheripid"></a>
## "AddEtherIpId" RPC API - Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices
### Description
Add New EtherIP / L2TPv3 over IPsec Client Setting to Accept EthreIP / L2TPv3 Client Devices. Add a new setting entry to enable the EtherIP / L2TPv3 over IPsec Server Function to accept client devices. In order to accept connections from routers by the EtherIP / L2TPv3 over IPsec Server Function, you have to define the relation table between an IPsec Phase 1 string which is presented by client devices of EtherIP / L2TPv3 over IPsec compatible router, and the designation of the destination Virtual Hub. After you add a definition entry by AddEtherIpId API, the defined connection setting to the Virtual Hub will be applied on the login-attepting session from an EtherIP / L2TPv3 over IPsec client device. The username and password in an entry must be registered on the Virtual Hub. An EtherIP / L2TPv3 client will be regarded as it connected the Virtual HUB with the identification of the above user information. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "AddEtherIpId",
  "params": {
    "Id_str": "id",
    "HubName_str": "hubname",
    "UserName_str": "username",
    "Password_str": "password"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Id_str": "id",
    "HubName_str": "hubname",
    "UserName_str": "username",
    "Password_str": "password"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Id_str` | `string` (ASCII) | Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules.
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to connect.
`UserName_str` | `string` (ASCII) | Specify the username to login to the destination Virtual Hub.
`Password_str` | `string` (ASCII) | Specify the password to login to the destination Virtual Hub.

***
<a id="getetheripid"></a>
## "GetEtherIpId" RPC API - Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions
### Description
Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetEtherIpId",
  "params": {
    "Id_str": "id"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Id_str": "id",
    "HubName_str": "hubname",
    "UserName_str": "username",
    "Password_str": "password"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Id_str` | `string` (ASCII) | Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules.
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to connect.
`UserName_str` | `string` (ASCII) | Specify the username to login to the destination Virtual Hub.
`Password_str` | `string` (ASCII) | Specify the password to login to the destination Virtual Hub.

***
<a id="deleteetheripid"></a>
## "DeleteEtherIpId" RPC API - Delete an EtherIP / L2TPv3 over IPsec Client Setting
### Description
Delete an EtherIP / L2TPv3 over IPsec Client Setting. This API deletes an entry to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "DeleteEtherIpId",
  "params": {
    "Id_str": "id"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Id_str": "id",
    "HubName_str": "hubname",
    "UserName_str": "username",
    "Password_str": "password"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Id_str` | `string` (ASCII) | Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules.
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to connect.
`UserName_str` | `string` (ASCII) | Specify the username to login to the destination Virtual Hub.
`Password_str` | `string` (ASCII) | Specify the password to login to the destination Virtual Hub.

***
<a id="enumetheripid"></a>
## "EnumEtherIpId" RPC API - Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions
### Description
Get the Current List of EtherIP / L2TPv3 Client Device Entry Definitions. This API gets and shows the list of entries to accept VPN clients by EtherIP / L2TPv3 over IPsec Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "EnumEtherIpId",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Settings": [
      {
        "Id_str": "id",
        "HubName_str": "hubname",
        "UserName_str": "username",
        "Password_str": "password"
      },
      {
        "Id_str": "id",
        "HubName_str": "hubname",
        "UserName_str": "username",
        "Password_str": "password"
      },
      {
        "Id_str": "id",
        "HubName_str": "hubname",
        "UserName_str": "username",
        "Password_str": "password"
      }
    ]
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Settings` | `Array object` | Setting list
`Id_str` | `string` (ASCII) | Specify an ISAKMP Phase 1 ID. The ID must be exactly same as a ID in the configuration of the EtherIP / L2TPv3 Client. You can specify IP address as well as characters as ID, if the EtherIP Client uses IP address as Phase 1 ID. If you specify '*' (asterisk), it will be a wildcard to match any clients which doesn't match other explicit rules.
`HubName_str` | `string` (ASCII) | Specify the name of the Virtual Hub to connect.
`UserName_str` | `string` (ASCII) | Specify the username to login to the destination Virtual Hub.
`Password_str` | `string` (ASCII) | Specify the password to login to the destination Virtual Hub.

***
<a id="setopenvpnsstpconfig"></a>
## "SetOpenVpnSstpConfig" RPC API - Set Settings for OpenVPN Clone Server Function
### Description
Set Settings for OpenVPN Clone Server Function. The VPN Server has the clone functions of OpenVPN software products by OpenVPN Technologies, Inc. Any OpenVPN Clients can connect to this VPN Server. The manner to specify a username to connect to the Virtual Hub, and the selection rule of default Hub by using this clone server functions are same to the IPsec Server functions. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetOpenVpnSstpConfig",
  "params": {
    "EnableOpenVPN_bool": false,
    "OpenVPNPortList_str": "openvpnportlist",
    "EnableSSTP_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "EnableOpenVPN_bool": false,
    "OpenVPNPortList_str": "openvpnportlist",
    "EnableSSTP_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`EnableOpenVPN_bool` | `boolean` | Specify true to enable the OpenVPN Clone Server Function. Specify false to disable.
`OpenVPNPortList_str` | `string` (ASCII) | Specify UDP ports to listen for OpenVPN. Multiple UDP ports can be specified with splitting by space or comma letters, for example: "1194, 2001, 2010, 2012". The default port for OpenVPN is UDP 1194. You can specify any other UDP ports.
`EnableSSTP_bool` | `boolean` | pecify true to enable the Microsoft SSTP VPN Clone Server Function. Specify false to disable.

***
<a id="getopenvpnsstpconfig"></a>
## "GetOpenVpnSstpConfig" RPC API - Get the Current Settings of OpenVPN Clone Server Function
### Description
Get the Current Settings of OpenVPN Clone Server Function. Get and show the current settings of OpenVPN Clone Server Function. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetOpenVpnSstpConfig",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "EnableOpenVPN_bool": false,
    "OpenVPNPortList_str": "openvpnportlist",
    "EnableSSTP_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`EnableOpenVPN_bool` | `boolean` | Specify true to enable the OpenVPN Clone Server Function. Specify false to disable.
`OpenVPNPortList_str` | `string` (ASCII) | Specify UDP ports to listen for OpenVPN. Multiple UDP ports can be specified with splitting by space or comma letters, for example: "1194, 2001, 2010, 2012". The default port for OpenVPN is UDP 1194. You can specify any other UDP ports.
`EnableSSTP_bool` | `boolean` | pecify true to enable the Microsoft SSTP VPN Clone Server Function. Specify false to disable.

***
<a id="getddnsclientstatus"></a>
## "GetDDnsClientStatus" RPC API - Show the Current Status of Dynamic DNS Function
### Description
Show the Current Status of Dynamic DNS Function. Get and show the current status of the Dynamic DNS function. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetDDnsClientStatus",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "Err_IPv4_u32": 0,
    "ErrStr_IPv4_utf": "errstr_ipv4",
    "Err_IPv6_u32": 0,
    "ErrStr_IPv6_utf": "errstr_ipv6",
    "CurrentHostName_str": "currenthostname",
    "CurrentFqdn_str": "currentfqdn",
    "DnsSuffix_str": "dnssuffix",
    "CurrentIPv4_str": "currentipv4",
    "CurrentIPv6_str": "currentipv6"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`Err_IPv4_u32` | `number` (uint32) | Last error code (IPv4)
`ErrStr_IPv4_utf` | `string` (UTF8) | Last error string (IPv4)
`Err_IPv6_u32` | `number` (uint32) | Last error code (IPv6)
`ErrStr_IPv6_utf` | `string` (UTF8) | Last error string (IPv6)
`CurrentHostName_str` | `string` (ASCII) | Current DDNS host name
`CurrentFqdn_str` | `string` (ASCII) | Current FQDN of the DDNS hostname
`DnsSuffix_str` | `string` (ASCII) | DDNS suffix
`CurrentIPv4_str` | `string` (ASCII) | Current IPv4 address of the VPN Server
`CurrentIPv6_str` | `string` (ASCII) | Current IPv6 address of the VPN Server

***
<a id="changeddnsclienthostname"></a>
## "ChangeDDnsClientHostname" RPC API - Set the Dynamic DNS Hostname
### Description
Set the Dynamic DNS Hostname. You must specify the new hostname on the StrValue_str field. You can use this API to change the hostname assigned by the Dynamic DNS function. The currently assigned hostname can be showen by the GetDDnsClientStatus API. The Dynamic DNS assigns a unique and permanent DNS hostname for this VPN Server. You can use that hostname to specify this VPN Server on the settings for VPN Client and VPN Bridge. You need not to register and keep a domain name. Also, if your ISP assignes you a dynamic (not-fixed) IP address, the corresponding IP address of your Dynamic DNS hostname will be automatically changed. It enables you to keep running the VPN Server by using only a dynamic IP address. Therefore, you need not any longer to keep static global IP addresses with expenses monthly costs. [Caution] To disable the Dynamic DNS Function, modify the configuration file of VPN Server. The "declare root" directive has the "declare DDnsClient" directive. In this directive, you can switch "bool Disable" from false to true, and reboot the VPN Server, then the Dynamic DNS Function will be disabled. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "ChangeDDnsClientHostname",
  "params": {
    "StrValue_str": "strvalue"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="regenerateservercert"></a>
## "RegenerateServerCert" RPC API - Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server
### Description
Generate New Self-Signed Certificate with Specified CN (Common Name) and Register on VPN Server. You can specify the new CN (common name) value on the StrValue_str field. You can use this API to replace the current certificate on the VPN Server to a new self-signed certificate which has the CN (Common Name) value in the fields. This API is convenient if you are planning to use Microsoft SSTP VPN Clone Server Function. Because of the value of CN (Common Name) on the SSL certificate of VPN Server must match to the hostname specified on the SSTP VPN client. This API will delete the existing SSL certificate of the VPN Server. It is recommended to backup the current SSL certificate and private key by using the GetServerCert API beforehand. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "RegenerateServerCert",
  "params": {
    "StrValue_str": "strvalue"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IntValue_u32": 0,
    "Int64Value_u64": 0,
    "StrValue_str": "strvalue",
    "UniStrValue_utf": "unistrvalue"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IntValue_u32` | `number` (uint32) | A 32-bit integer field
`Int64Value_u64` | `number` (uint64) | A 64-bit integer field
`StrValue_str` | `string` (ASCII) | An Ascii string field
`UniStrValue_utf` | `string` (UTF8) | An UTF-8 string field

***
<a id="makeopenvpnconfigfile"></a>
## "MakeOpenVpnConfigFile" RPC API - Generate a Sample Setting File for OpenVPN Client
### Description
Generate a Sample Setting File for OpenVPN Client. Originally, the OpenVPN Client requires a user to write a very difficult configuration file manually. This API helps you to make a useful configuration sample. What you need to generate the configuration file for the OpenVPN Client is to run this API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "MakeOpenVpnConfigFile",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ServerName_str": "servername",
    "FilePath_str": "filepath",
    "Offset_u32": 0,
    "Buffer_bin": "SGVsbG8gV29ybGQ="
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ServerName_str` | `string` (ASCII) | Server name
`FilePath_str` | `string` (ASCII) | File Path
`Offset_u32` | `number` (uint32) | Offset to download. You have to call the ReadLogFile API multiple times to download the entire log file with requesting a part of the file by specifying the Offset_u32 field.
`Buffer_bin` | `string` (Base64 binary) | Received buffer

***
<a id="setspeciallistener"></a>
## "SetSpecialListener" RPC API - Enable / Disable the VPN over ICMP / VPN over DNS Server Function
### Description
Enable / Disable the VPN over ICMP / VPN over DNS Server Function. You can establish a VPN only with ICMP or DNS packets even if there is a firewall or routers which blocks TCP/IP communications. You have to enable the following functions beforehand. Warning: Use this function for emergency only. It is helpful when a firewall or router is misconfigured to blocks TCP/IP, but either ICMP or DNS is not blocked. It is not for long-term stable using. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetSpecialListener",
  "params": {
    "VpnOverIcmpListener_bool": false,
    "VpnOverDnsListener_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "VpnOverIcmpListener_bool": false,
    "VpnOverDnsListener_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`VpnOverIcmpListener_bool` | `boolean` | The flag to activate the VPN over ICMP server function
`VpnOverDnsListener_bool` | `boolean` | The flag to activate the VPN over DNS function

***
<a id="getspeciallistener"></a>
## "GetSpecialListener" RPC API - Get Current Setting of the VPN over ICMP / VPN over DNS Function
### Description
Get Current Setting of the VPN over ICMP / VPN over DNS Function. Get and show the current VPN over ICMP / VPN over DNS Function status. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetSpecialListener",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "VpnOverIcmpListener_bool": false,
    "VpnOverDnsListener_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`VpnOverIcmpListener_bool` | `boolean` | The flag to activate the VPN over ICMP server function
`VpnOverDnsListener_bool` | `boolean` | The flag to activate the VPN over DNS function

***
<a id="getazurestatus"></a>
## "GetAzureStatus" RPC API - Show the current status of VPN Azure function
### Description
Show the current status of VPN Azure function. Get and show the current status of the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetAzureStatus",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IsEnabled_bool": false,
    "IsConnected_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IsEnabled_bool` | `boolean` | Whether VPN Azure Function is Enabled
`IsConnected_bool` | `boolean` | Whether connection to VPN Azure Cloud Server is established

***
<a id="setazurestatus"></a>
## "SetAzureStatus" RPC API - Enable / Disable VPN Azure Function
### Description
Enable / Disable VPN Azure Function. Enable or disable the VPN Azure function. VPN Azure makes it easier to establish a VPN Session from your home PC to your office PC. While a VPN connection is established, you can access to any other servers on the private network of your company. You don't need a global IP address on the office PC (VPN Server). It can work behind firewalls or NATs. No network administrator's configuration required. You can use the built-in SSTP-VPN Client of Windows in your home PC. VPN Azure is a cloud VPN service operated by SoftEther Corporation. VPN Azure is free of charge and available to anyone. Visit http://www.vpnazure.net/ to see details and how-to-use instructions. The VPN Azure hostname is same to the hostname of the Dynamic DNS setting, but altering the domain suffix to "vpnazure.net". To change the hostname use the ChangeDDnsClientHostname API. To call this API, you must have VPN Server administrator privileges. This API cannot be invoked on VPN Bridge. You cannot execute this API for Virtual Hubs of VPN Servers operating as a cluster.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetAzureStatus",
  "params": {
    "IsEnabled_bool": false
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "IsEnabled_bool": false,
    "IsConnected_bool": false
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`IsEnabled_bool` | `boolean` | Whether VPN Azure Function is Enabled
`IsConnected_bool` | `boolean` | Whether connection to VPN Azure Cloud Server is established

***
<a id="getddnsinternetsettng"></a>
## "GetDDnsInternetSettng" RPC API - Get the Proxy Settings for Connecting to the DDNS server
### Description
Get the Proxy Settings for Connecting to the DDNS server.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetDDnsInternetSettng",
  "params": {}
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ProxyType_u32": 0,
    "ProxyHostName_str": "proxyhostname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "proxyusername",
    "ProxyPassword_str": "proxypassword"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ProxyType_u32` | `number` (enum) | Type of proxy server<BR>Values:<BR>`0`: Direct TCP connection<BR>`1`: Connection via HTTP proxy server<BR>`2`: Connection via SOCKS proxy server
`ProxyHostName_str` | `string` (ASCII) | Proxy server host name
`ProxyPort_u32` | `number` (uint32) | Proxy server port number
`ProxyUsername_str` | `string` (ASCII) | Proxy server user name
`ProxyPassword_str` | `string` (ASCII) | Proxy server password

***
<a id="setddnsinternetsettng"></a>
## "SetDDnsInternetSettng" RPC API - Set the Proxy Settings for Connecting to the DDNS server
### Description
Set the Proxy Settings for Connecting to the DDNS server.

### Input JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "SetDDnsInternetSettng",
  "params": {
    "ProxyType_u32": 0,
    "ProxyHostName_str": "proxyhostname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "proxyusername",
    "ProxyPassword_str": "proxypassword"
  }
}
```

### Output JSON-RPC Format
```json
{
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "result": {
    "ProxyType_u32": 0,
    "ProxyHostName_str": "proxyhostname",
    "ProxyPort_u32": 0,
    "ProxyUsername_str": "proxyusername",
    "ProxyPassword_str": "proxypassword"
  }
}
```

### Parameters

Name | Type | Description
--- | --- | ---
`ProxyType_u32` | `number` (enum) | Type of proxy server<BR>Values:<BR>`0`: Direct TCP connection<BR>`1`: Connection via HTTP proxy server<BR>`2`: Connection via SOCKS proxy server
`ProxyHostName_str` | `string` (ASCII) | Proxy server host name
`ProxyPort_u32` | `number` (uint32) | Proxy server port number
`ProxyUsername_str` | `string` (ASCII) | Proxy server user name
`ProxyPassword_str` | `string` (ASCII) | Proxy server password

***
Automatically generated at 2019-07-10 14:36:11 by vpnserver-jsonrpc-codegen.  
Copyright (c) 2014-2019 [SoftEther VPN Project](https://www.softether.org/) under the Apache License 2.0.  

